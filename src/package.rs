use anyhow::{Result, Context, bail};
use directories::ProjectDirs;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::os::unix::io::AsRawFd;
use tar::Archive;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, Signer, SigningKey};
use std::convert::TryInto;

const REGISTRY_URL: &str = "https://pkgd.atticl.com";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PackageManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub checksum: Option<String>,
    #[serde(default)]
    pub dependencies: Option<Vec<String>>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalPackageRecord {
    pub manifest: PackageManifest,
    pub files: Vec<String>,
}

#[derive(Deserialize)]
struct AuthorKeysResponse {
    keys: Vec<String>,
}

pub fn get_db_dir(target_root: &Path) -> PathBuf {
    if target_root == Path::new("/") {
        PathBuf::from("/var/lib/pkgd/installed")
    } else {
        // If it's a user-local root, follow XDG-like structure: root/share/pkgd/installed
        target_root.join("share/pkgd/installed")
    }
}

pub fn acquire_lock(target_root: &Path) -> Result<File> {
    let db_dir = get_db_dir(target_root);
    let _ = std::fs::create_dir_all(&db_dir);

    let lock_path = db_dir.join(".pkgd.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)?;

    println!("Acquiring exclusive database lock...");

    unsafe {
        let fd = file.as_raw_fd();

        if libc::flock(fd, libc::LOCK_EX) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }

    Ok(file)
}

pub fn download_and_install_package(
    package_name: &str,
    target_root: &Path,
) -> Result<()> {
    let mut resolved = HashSet::new();
    resolve_and_install(package_name, target_root, &mut resolved)
}

fn resolve_and_install(
    package_identifier: &str,
    target_root: &Path,
    resolved: &mut HashSet<String>,
) -> Result<()> {
    let (package_name, requested_version) = if let Some(idx) = package_identifier.find('@') {
        (&package_identifier[..idx], Some(&package_identifier[idx + 1..]))
    } else {
        (package_identifier, None)
    };

    if resolved.contains(package_name) {
        return Ok(());
    }

    let db_dir = get_db_dir(target_root);
    let db_file_path = db_dir.join(format!("{}.json", package_name));
    if db_file_path.exists() {
        let file = File::open(&db_file_path)?;
        let local_record: LocalPackageRecord = serde_json::from_reader(file)?;

        if let Some(req_ver) = requested_version {
            if local_record.manifest.version == req_ver {
                println!("Dependency '{}@{}' is already installed. Skipping.", package_name, req_ver);
                resolved.insert(package_name.to_string());
                return Ok(());
            } else {
                println!("Different version of '{}' installed ({}). Replacing with requested version {}...",
                        package_name, local_record.manifest.version, req_ver);
                remove_package(package_name, target_root);
            }
        } else {
            println!("Dependency '{}' is already installed. Skipping.", package_name);
            resolved.insert(package_name.to_string());
            return Ok(());
        }
    }

    let api_url = if let Some(req_ver) = requested_version {
        format!("{}/api/packages/{}/{}", REGISTRY_URL, package_name, req_ver)
    } else {
        format!("{}/api/packages/{}", REGISTRY_URL, package_name)
    };

    println!("Fetching manifest from: {}", api_url);

    let response = reqwest::blocking::get(&api_url)
        .with_context(|| format!("Failed to connect to registry to fetch manifest for {}", package_identifier))?;
    
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        bail!("Package '{}' not found in remote registry.", package_identifier);
    }

    let manifest: PackageManifest = response.json()
        .with_context(|| format!("Failed to parse manifest JSON for {}", package_identifier))?;

    println!("Found remote package: {} ({})", manifest.name, manifest.version);

    resolved.insert(package_name.to_string());

    if let Some(deps) = &manifest.dependencies {
        for dep in deps {
            println!("Resolving dependency '{}' for package '{}'...", dep, package_name);
            resolve_and_install(dep, target_root, resolved)?;
        }
    }

    let tarball_filename = format!("{}-{}.tar.gz", manifest.name, manifest.version);
    let download_url = format!("{}/download/{}", REGISTRY_URL, tarball_filename);
    println!("Downloading tarball from: {}", download_url);

    let mut tarball_response = reqwest::blocking::get(&download_url)
        .with_context(|| format!("Failed to download tarball for {}", package_name))?;
        
    if !tarball_response.status().is_success() {
        bail!("Failed to download tarball from registry server. Status: {}", tarball_response.status());
    }

    let tmp_dir = std::env::temp_dir();
    let tmp_archive_path = tmp_dir.join(&tarball_filename);
    let mut tmp_file = File::create(&tmp_archive_path)?;

    tarball_response.copy_to(&mut tmp_file)?;

    if let Some(expected_hash) = &manifest.checksum {
        println!("Verifying SHA-256 checksum for {}...", package_name);
        let tarball_bytes = fs::read(&tmp_archive_path)?;

        let mut hasher = Sha256::new();
        hasher.update(&tarball_bytes);
        let actual_hash = hex::encode(hasher.finalize());

        if actual_hash != *expected_hash {
            let _ = fs::remove_file(&tmp_archive_path);
            bail!(
                "SECURITY ALERT: Checksum mismatch for {}!\nExpected: {}\nGot:      {}",
                package_name, expected_hash, actual_hash
            );
        }
        println!("Checksum verified successfully.");

        if let Some(sig_hex) = &manifest.signature {
            println!("Verifying Ed25519 signature for author '{}'...", manifest.author);
            
            let sig_bytes = hex::decode(sig_hex).context("Signature in manifest is not valid hex")?;
            let signature = Signature::from_slice(&sig_bytes).context("Invalid signature length")?;
            
            let author_keys_dir = get_db_dir(target_root).join("keys").join(&manifest.author);
            let mut verified = false;

            if author_keys_dir.exists() {
                for entry in fs::read_dir(&author_keys_dir)? {
                    let path = entry?.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("pub") {
                        if let Ok(pub_hex) = fs::read_to_string(&path) {
                            if let Ok(pub_bytes) = hex::decode(pub_hex.trim()) {
                                if let Ok(pub_bytes_arr) = pub_bytes.try_into() {
                                    if let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_bytes_arr) {
                                        if verifying_key.verify(&tarball_bytes, &signature).is_ok() {
                                            verified = true;
                                            println!("Signature verified against local trusted key.");
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if !verified {
                println!("No matching local key found. Fetching public keys from registry (TOFU)...");
                let keys_api_url = format!("{}/api/authors/{}/keys", REGISTRY_URL, manifest.author);
                let keys_response = reqwest::blocking::get(&keys_api_url)?;

                if keys_response.status().is_success() {
                    let keys_data: AuthorKeysResponse = keys_response.json()?;
                    let _ = fs::create_dir_all(&author_keys_dir)?;

                    for (i, pub_hex) in keys_data.keys.iter().enumerate() {
                        if let Ok(pub_bytes) = hex::decode(pub_hex.trim()) {
                            if let Ok(pub_bytes_arr) = pub_bytes.try_into() {
                                if let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_bytes_arr) {
                                    if verifying_key.verify(&tarball_bytes, &signature).is_ok() {
                                        verified = true;
                                        println!("Signature verified against newly fetched key!");
                                    }
                                    
                                    let key_filename = format!("key_{}.pub", i);
                                    let key_path = author_keys_dir.join(key_filename);
                                    if !key_path.exists() {
                                        fs::write(&key_path, pub_hex.trim())?;
                                        println!("Saved new trusted key to {:?}", key_path);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    println!("Warning: Server returned {} when fetching keys.", keys_response.status());
                }
            }

            if !verified {
                let _ = fs::remove_file(&tmp_archive_path);
                bail!("SECURITY ALERT: Remote host identification has changed or is missing! Signature does not match any trusted keys for author '{}'.", manifest.author);
            }
        }
    }

    println!("Download complete for {}. Handing off to local installation pipeline...", package_name);

    install_package(&tmp_archive_path, target_root)?;

    let _ = fs::remove_file(tmp_archive_path);

    Ok(())
}

pub fn install_package(archive_path: &Path, target_root: &Path) -> Result<()> {
    let file = File::open(archive_path)?;
    let tar_gz = GzDecoder::new(file);
    let mut archive = Archive::new(tar_gz);

    let mut manifest: Option<PackageManifest> = None;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        let clean_path = path.strip_prefix(".").unwrap_or(&path);

        if clean_path.to_str() == Some("manifest.json") {
            manifest = Some(serde_json::from_reader(&mut entry)?);
            break;
        }
    }

    let manifest = match manifest {
        Some(m) => m,
        None => bail!("Failed to find manifest.json in package archive"),
    };

    println!("Extracting package: {} ({})", manifest.name, manifest.version);

    let file = File::open(archive_path)?;
    let tar_gz = GzDecoder::new(file);
    let mut archive = Archive::new(tar_gz);

    let mut installed_files = Vec::new();

    let extraction_result: Result<()> = (|| {
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf();

            let clean_path = path.strip_prefix(".").unwrap_or(&path);

            if clean_path.to_str() != Some("manifest.json") {
                let mut safe_path = clean_path;

                while let Ok(stripped) = safe_path.strip_prefix("/") {
                    safe_path = stripped;
                }

                let dest_path = target_root.join(safe_path);

                if let Some(parent) = dest_path.parent() {
                    let _ = std::fs::create_dir_all(parent)?;
                }

                entry.unpack(&dest_path)?;
                println!("Extracted: {:?}", dest_path);

                if let Some(path_str) = safe_path.to_str() {
                    installed_files.push(path_str.to_string());
                }
            }
        }
        Ok(())
    })();

    if let Err(e) = extraction_result {
        println!("Error during extraction: {}. Initiating rollback...", e);

        for file_path_str in installed_files.iter().rev() {
            let full_path = target_root.join(file_path_str);

            if full_path.exists() && full_path.is_file() {
                let _ = fs::remove_file(&full_path);
                println!("Rolled back file: {:?}", full_path);
            }

            if let Some(mut parent) = full_path.parent() {
                while parent != target_root {
                    if parent.exists() && fs::read_dir(parent).map(|mut d| d.next().is_none()).unwrap_or(false) {
                        let _ = fs::remove_dir(parent);
                        println!("Rolled back empty directory: {:?}", parent);
                    } else {
                        break;
                    }
                    if let Some(p) = parent.parent() {
                        parent = p;
                    } else {
                        break;
                    }
                }
            }
        }

        bail!("Installation failed and was rolled back safely: {}", e);
    }

    let record = LocalPackageRecord {
        manifest: manifest.clone(),
        files: installed_files,
    };
    
    let db_dir = get_db_dir(target_root);
    let _ = std::fs::create_dir_all(&db_dir)?;

    let db_file_path = db_dir.join(format!("{}.json", record.manifest.name));
    let db_file = File::create(db_file_path)?;
    serde_json::to_writer_pretty(db_file, &record)?;

    println!("Successfully registered {} in local database.", record.manifest.name);
    Ok(())
}

pub fn list_packages(target_root: &Path) -> Result<()> {
    let db_dir = get_db_dir(target_root);

    if !db_dir.exists() {
        println!("No packages installed.");
        return Ok(());
    }

    println!("{:<20} {:<10} {}", "PACKAGE", "VERSION", "DESCRIPTION");
    println!("{}", "-".repeat(60));

    for entry in fs::read_dir(db_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
            let file = File::open(path)?;
            let record: LocalPackageRecord = serde_json::from_reader(file)?;

            println!(
                "{:<20} {:<10} {}",
                record.manifest.name, record.manifest.version, record.manifest.description
            );
        }
    }

    Ok(())
}

pub fn update_packages(
    package_name: Option<&str>,
    target_root: &Path,
) -> Result<()> {
    let db_dir = get_db_dir(target_root);

    if !db_dir.exists() {
        println!("No packages installed.");
        return Ok(());
    }

    let mut packages_to_check = Vec::new();

    if let Some(name) = package_name {
        let db_file_path = db_dir.join(format!("{}.json", name));
        if !db_file_path.exists() {
            bail!("Package '{}' is not installed.", name);
        }
        packages_to_check.push(name.to_string());
    } else {
        for entry in fs::read_dir(&db_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    packages_to_check.push(name.to_string());
                }   
            }
        }
    }

    let mut updates_available = Vec::new();

    for pkg_name in packages_to_check {
        let db_file_path = db_dir.join(format!("{}.json", &pkg_name));
        let file = File::open(&db_file_path)?;
        let local_record: LocalPackageRecord = serde_json::from_reader(file)?;

        let api_url = format!("{}/api/packages/{}", REGISTRY_URL, pkg_name);

        let response = reqwest::blocking::get(&api_url)?;
        if response.status() == reqwest::StatusCode::OK {
            let remote_manifest: PackageManifest = response.json()?;

            if remote_manifest.version != local_record.manifest.version {
                println!(
                    "Update available for {}: {} -> {}",
                    pkg_name, local_record.manifest.version, remote_manifest.version
                );
                updates_available.push(pkg_name);
            } else {
                println!("{} is up to date ({}).", pkg_name, local_record.manifest.version);
            }
        } else {
            println!("Warning: Could not check updates for {} (server returned {})", pkg_name, response.status());
        }
    }

    if updates_available.is_empty() {
        println!("Everything is up to date!");
        return Ok(());
    }

    for pkg_name in updates_available {
        println!("\n--- Updating {} ---", pkg_name);

        remove_package(&pkg_name, target_root)?;
        download_and_install_package(&pkg_name, target_root)?;

        println!("Successfully updated: {}!", pkg_name);
    }

    Ok(())
}

pub fn remove_package(package_name: &str, target_root: &Path) -> Result<()> {
    let db_dir = get_db_dir(target_root);
    let db_file_path = db_dir.join(format!("{}.json", package_name));

    if !db_file_path.exists() {
        bail!("Package '{}' is not installed.", package_name);
    }

    let file = File::open(&db_file_path)?;
    let record: LocalPackageRecord = serde_json::from_reader(file)?;

    println!("Removing package: {} ({})", record.manifest.name, record.manifest.version);

    for file_path_str in &record.files {
        let full_path = target_root.join(file_path_str);

        if full_path.exists() {
            if full_path.is_file() {
                fs::remove_file(&full_path)?;
                println!("Deleted file: {:?}", full_path);
            }
        } else {
            println!("Warning: File missing during uninstall: {:?}", full_path);
        }

        if let Some(mut parent) = full_path.parent() {
            while parent != target_root {
                if parent.exists() && fs::read_dir(parent)?.next().is_none() {
                    fs::remove_dir(parent)?;
                    println!("Deleted empty directory: {:?}", parent);
                } else {
                    break;
                }
                if let Some(p) = parent.parent() {
                    parent = p;
                } else {
                    break;
                }
            }
        }
    }

    fs::remove_file(db_file_path)?;
    println!("Successfully removed {} from local database.", package_name);

    Ok(())
}

fn get_credentials_path() -> Result<PathBuf> {
    if let Some(proj_dirs) = ProjectDirs::from("com", "atticl", "pkgd") {
        let config_dir = proj_dirs.config_dir();
        return Ok(config_dir.join("credentials"));
    }
    
    let home = std::env::var("HOME").context("Could not find HOME directory. Are you on Linux/macOS?")?;
    Ok(Path::new(&home).join(".pkgd").join("credentials"))
}

fn get_api_token() -> Result<String> {
    if let Ok(token) = std::env::var("PKGD_API_KEY") {
        return Ok(token);
    }

    let cred_path = get_credentials_path()?;
    if cred_path.exists() {
        let token = fs::read_to_string(cred_path)?;
        return Ok(token.trim().to_string());
    }

    bail!("Not logged in. Please run `pkgd login <token>` or set the PKGD_API_KEY environment variable.");
}

pub fn publish_package(source_dir: &Path) -> Result<()> {
    let api_key = get_api_token()?;

    let manifest_path = source_dir.join("manifest.json");
    if !manifest_path.exists() {
        bail!("manifest.json not found in the source directory.");
    }

    let manifest_str = fs::read_to_string(&manifest_path)?;
    let mut manifest: PackageManifest = serde_json::from_str(&manifest_str)?;

    println!("Packaging {} version {}...", manifest.name, manifest.version);

    let tarball_name = format!("{}-{}.tar.gz", manifest.name, manifest.version);
    let tmp_tar_path = std::env::temp_dir().join(&tarball_name);
    let tar_file = File::create(&tmp_tar_path)?;

    let enc = GzEncoder::new(tar_file, Compression::default());
    let mut tar_builder = tar::Builder::new(enc);

    tar_builder.append_dir_all(".", source_dir)?;
    tar_builder.into_inner()?.finish()?;

    println!("Archive created successfully. Uploading to registry...");

    let tarball_bytes = fs::read(&tmp_tar_path)?;

    let priv_key_path = get_credentials_path()?.parent().unwrap().join("id_ed25519");
    if priv_key_path.exists() {
        println!("Signing package with local Ed25519 key...");
        let priv_key_hex = fs::read_to_string(&priv_key_path)?;
        
        let priv_key_bytes = hex::decode(priv_key_hex.trim())
            .context("Private key is not valid hex")?;
            
        let priv_key_arr: [u8; 32] = priv_key_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Private key must be exactly 32 bytes"))?;
            
        let signing_key = SigningKey::from_bytes(&priv_key_arr);
        let signature = signing_key.sign(&tarball_bytes);
        
        manifest.signature = Some(hex::encode(signature.to_bytes()));
    } else {
        println!("Warning: No local Ed25519 key found at {:?}. Publishing WITHOUT signature.", priv_key_path);
        println!("Run `pkgd keygen` to create one.");
    }

    let final_manifest_str = serde_json::to_string(&manifest)?;

    let part_manifest = reqwest::blocking::multipart::Part::text(final_manifest_str);
    let part_tarball = reqwest::blocking::multipart::Part::bytes(tarball_bytes)
        .file_name(tarball_name)
        .mime_str("application/gzip")?;

    let form = reqwest::blocking::multipart::Form::new()
        .part("manifest", part_manifest)
        .part("tarball", part_tarball);

    let client = reqwest::blocking::Client::new();
    let res = client
        .post(format!("{}/api/publish", REGISTRY_URL))
        .bearer_auth(api_key)
        .multipart(form)
        .send()?;

    if res.status().is_success() {
        println!("Package published successfully!");
    } else if res.status() == reqwest::StatusCode::UNAUTHORIZED {
        println!("Unauthorized! Invalid API token.");
    } else if res.status() == reqwest::StatusCode::FORBIDDEN {
        println!("Forbidden! You do not own this package.");
    } else {
        println!(
            "Failed to publish package. Server responded with: {}",
            res.status()
        );
    }

    let _ = fs::remove_file(tmp_tar_path);

    Ok(())
}

pub fn login(token: &str) -> Result<()> {
    let cred_path = get_credentials_path()?;

    if let Some(parent) = cred_path.parent() {
        let _ = fs::create_dir_all(parent)?;
    }

    fs::write(&cred_path, token.trim())?;

    println!("Logged in successfully. Token saved to {:?}", cred_path);
    Ok(())
}

pub fn generate_keys() -> Result<()> {
    let cred_dir = get_credentials_path()?.parent().unwrap().to_path_buf();
    let _ = fs::create_dir_all(&cred_dir);

    let priv_path = cred_dir.join("id_ed25519");
    let pub_path = cred_dir.join("id_ed25519.pub");

    if priv_path.exists() {
        bail!("A private key already exists at {:?}. Aborting to prevent overwrite.", priv_path);
    }

    print!("Generating new Ed25519 keypair...");
    let mut csprng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut csprng);
    let veryfing_key = VerifyingKey::from(&signing_key);

    fs::write(&priv_path, hex::encode(signing_key.to_bytes()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600))?;
    }

    let pub_hex = hex::encode(veryfing_key.to_bytes());
    fs::write(&pub_path, &pub_hex)?;

    println!("Keypair generated successfully!");
    println!("Private key: {:?}", priv_path);
    println!("Public key:  {:?}", pub_path);
    println!("\n--- ACTION REQUIRED ---");
    println!("Please copy the following public key and add it to your account on pkgd.atticl.com:\n");
    println!("{}", pub_hex);

    Ok(())
}
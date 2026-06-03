use anyhow::{Result, Context, bail};
use directories::ProjectDirs;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize, de};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::os::unix::io::AsRawFd;
use tar::Archive;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, Signer, SigningKey};
use std::convert::TryInto;
use indicatif::{ProgressBar, ProgressStyle};
use std::io;
use std::io::{Write};

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
    #[serde(default)]
    pub installed_as_dependency: bool,
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    pub username: &'a str,
    pub password: &'a str,
}

#[derive(Deserialize)]
struct LoginResponse {
    pub token: String,
}

#[derive(Deserialize)]
struct KeyInfo {
    name: String,
    key: String,
}

#[derive(Deserialize)]
struct AuthorKeysResponse {
    pub author: String,
    pub keys: Vec<KeyInfo>,
}

pub fn get_db_dir(target_root: &Path) -> PathBuf {
    if target_root == Path::new("/") {
        PathBuf::from("/var/lib/pkgd/installed")
    } else {
        // If it's a user-local root, follow XDG-like structure: root/share/pkgd/installed
        target_root.join("share/pkgd/installed")
    }
}

fn parse_identifier(id: &str) -> (&str, Option<&str>) {
    if let Some(idx) = id.rfind('@') {
        if idx > 0 {
            return (&id[..idx], Some(&id[idx + 1..]));
        }
    }
    (id, None)
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

fn get_all_installed_records(target_root: &Path) -> Result<Vec<LocalPackageRecord>> {
    let mut records = Vec::new();
    let db_dir = get_db_dir(target_root);
    if !db_dir.exists() { return Ok(records); }

    let mut dirs_to_check = vec![db_dir];

    while let Some(dir) = dirs_to_check.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                dirs_to_check.push(path);
            } else if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                if path.file_name().and_then(|s| s.to_str()) == Some(".pkgd.lock") {
                    continue;
                }
                if let Ok(file) = File::open(&path) {
                    if let Ok(record) = serde_json::from_reader::<_, LocalPackageRecord>(file) {
                        records.push(record);
                    }
                }
            }
        }
    }
    Ok(records)
}

pub fn download_and_install_package(
    package_name: &str,
    target_root: &Path,
) -> Result<()> {
    let mut resolved = HashSet::new();
    resolve_and_install(package_name, target_root, false, &mut resolved)
}

fn resolve_and_install(
    package_identifier: &str,
    target_root: &Path,
    is_dependency: bool,
    resolved: &mut HashSet<String>,
) -> Result<()> {
    let (package_name, requested_version) = parse_identifier(package_identifier);

    if resolved.contains(package_name) {
        return Ok(());
    }

    let db_dir = get_db_dir(target_root);
    let db_file_path = db_dir.join(format!("{}.json", package_name));

    if let Some(parent) = db_file_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

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
                let _ = remove_package(package_name, target_root);
            }
        } else {
            println!("Dependency '{}' is already installed. Skipping.", package_name);
            resolved.insert(package_name.to_string());
            return Ok(());
        }
    }

    let safe_name = urlencoding::encode(package_name);

    let api_url = if let Some(req_ver) = requested_version {
        format!("{}/api/packages/{}/{}", REGISTRY_URL, safe_name, req_ver)
    } else {
        format!("{}/api/packages/{}", REGISTRY_URL, safe_name)
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
            resolve_and_install(dep, target_root, true, resolved)?;
        }
    }

    let safe_manifest_name = manifest.name.replace('/', "_");
    let tarball_filename = format!("{}-{}.tar.gz", safe_manifest_name, manifest.version);


    let encoded_filename = urlencoding::encode(&tarball_filename);
    let download_url = format!("{}/download/{}", REGISTRY_URL, encoded_filename);

    println!("Downloading tarball from: {}", download_url);

    let tarball_response = reqwest::blocking::get(&download_url)
        .with_context(|| format!("Failed to download tarball for {}", package_name))?;
        
    if !tarball_response.status().is_success() {
        bail!("Failed to download tarball from registry server. Status: {}", tarball_response.status());
    }

    let total_size = tarball_response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|ct_len| ct_len.to_str().ok())
        .and_then(|ct_len| ct_len.parse::<u64>().ok())
        .unwrap_or(0);

    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})"
        )
        .unwrap()
        .progress_chars("#>-")
    );
    pb.set_message(format!("Downloading {}", package_name));

    let tmp_dir = std::env::temp_dir();
    let tmp_archive_path = tmp_dir.join(&tarball_filename);
    let mut tmp_file = File::create(&tmp_archive_path)?;

    let mut source = pb.wrap_read(tarball_response);

    io::copy(&mut source, &mut tmp_file)?;

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
                    let raw_text = keys_response.text()?;
                    
                    match serde_json::from_str::<AuthorKeysResponse>(&raw_text) {
                        Ok(keys_data) => {
                            let _ = fs::create_dir_all(&author_keys_dir)?;

                            for key_info in keys_data.keys.iter() {
                                if let Ok(pub_bytes) = hex::decode(key_info.key.trim()) {
                                    if let Ok(pub_bytes_arr) = pub_bytes.try_into() {
                                        if let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_bytes_arr) {
                                            if verifying_key.verify(&tarball_bytes, &signature).is_ok() {
                                                verified = true;
                                                println!("Signature verified against newly fetched key ('{}')!", key_info.name);
                                            }
                                            
                                            let safe_name = key_info.name.replace(|c: char| !c.is_alphanumeric(), "_");
                                            let key_filename = format!("{}.pub", safe_name);
                                            let key_path = author_keys_dir.join(key_filename);
                                            if !key_path.exists() {
                                                fs::write(&key_path, key_info.key.trim())?;
                                                println!("Saved new trusted key to {:?}", key_path);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("Warning: Registry returned invalid JSON. ({})", e);
                            println!("Raw server response: {}", raw_text);
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

    install_package(&tmp_archive_path, target_root, is_dependency)?;

    let _ = fs::remove_file(tmp_archive_path);

    Ok(())
}

pub fn install_package(archive_path: &Path, target_root: &Path, installed_as_dependency: bool) -> Result<()> {
    let file = File::open(archive_path)?;
    let tar_gz = GzDecoder::new(file);
    let mut archive = Archive::new(tar_gz);

    let mut manifest: Option<PackageManifest> = None;
    let mut collisions = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        let clean_path = path.strip_prefix(".").unwrap_or(&path);

        if clean_path.to_str() == Some("manifest.json") {
            manifest = Some(serde_json::from_reader(&mut entry)?);
            continue;
        }

        if !entry.header().entry_type().is_dir() {
            let mut safe_path = clean_path;
            while let Ok(stripped) = safe_path.strip_prefix("/") {
                safe_path = stripped;
            }

            let dest_path = target_root.join(safe_path);

            if dest_path.exists() {
                collisions.push(dest_path.to_string_lossy().to_string());
            }
        }
    }

    let manifest = match manifest {
        Some(m) => m,
        None => bail!("Failed to find manifest.json in package archive"),
    };

    if !collisions.is_empty() {
        bail!(
            "FILE COLLISION DETECTED!\nThe following files already exist on the system and belong to another package:\n  - {}\n\nAborting installation to prevent system corruption.",
            collisions.join("\n  - ")
        );
    }

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
        installed_as_dependency,
    };
    
    let db_dir = get_db_dir(target_root);
    let db_file_path = db_dir.join(format!("{}.json", record.manifest.name));

    if let Some(parent) = db_file_path.parent() {
        fs::create_dir_all(parent)?;
    }

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

pub fn update_packages(package_name: Option<&str>, target_root: &Path) -> Result<()> {
    let packages_to_update = if let Some(name) = package_name {
        vec![name.to_string()]
    } else {
        let records = get_all_installed_records(target_root)?;
        records.into_iter().map(|r| r.manifest.name).collect()
    };

    let mut updated_count = 0;

    for pkg_name in packages_to_update {
        let safe_name = urlencoding::encode(&pkg_name);
        let api_url = format!("{}/api/packages/{}", REGISTRY_URL, safe_name);
        
        let response = reqwest::blocking::get(&api_url)?;
        if !response.status().is_success() {
            println!("Warning: Could not check updates for {} (Server returned {})", pkg_name, response.status());
            continue;
        }

        let remote_manifest: PackageManifest = response.json()?;
        
        let db_file_path = get_db_dir(target_root).join(format!("{}.json", pkg_name));
        if let Ok(file) = std::fs::File::open(&db_file_path) {
            if let Ok(local_record) = serde_json::from_reader::<_, LocalPackageRecord>(file) {
                
                if remote_manifest.version != local_record.manifest.version {
                    println!("Updating {} from v{} to v{}...", pkg_name, local_record.manifest.version, remote_manifest.version);
                    
                    remove_package(&pkg_name, target_root)?;
                    download_and_install_package(&pkg_name, target_root)?;
                    
                    updated_count += 1;
                } else {
                    println!("{} is already up to date (v{}).", pkg_name, local_record.manifest.version);
                }
            }
        }
    }

    println!("Update complete. {} packages updated.", updated_count);
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

    let safe_name = manifest.name.replace('/', "_");
    let tarball_name = format!("{}-{}.tar.gz", safe_name, manifest.version);
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

pub fn login(token: Option<String>) -> Result<()> {
    let final_token = if let Some(t) = token {
        t
    } else {
        println!("Log in to {}", REGISTRY_URL);

        print!("Username: ");
        io::stdout().flush()?;
        let mut username = String::new();
        io::stdin().read_line(&mut username)?;
        let username = username.trim();

        let password = rpassword::prompt_password("Password: ")?;

        println!("Authenticating...");

        let client = reqwest::blocking::Client::new();
        let res = client
            .post(format!("{}/api/login", REGISTRY_URL))
            .json(&LoginRequest {
                username,
                password: &password,
            })
            .send()
            .context("Failed to connect to the registry for authentication")?;

        if res.status().is_success() {
            let login_data: LoginResponse = res.json()
                .context("Server returned invalid JSON for login response")?;
            login_data.token
        } else if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            bail!("Invalid username or password.");
        } else {
            bail!("Login failed. Server returned HTTP {}", res.status());
        }
    };

    let cred_path = get_credentials_path()?;
    if let Some(parent) = cred_path.parent() {
        let _ = fs::create_dir_all(parent)?;
    }

    fs::write(&cred_path, final_token.trim());

    println!("Logged in successfully. Credentials saved.");
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

pub fn autoremove_packages(target_root: &Path) -> Result<()> {
    let db_dir = get_db_dir(target_root);
    if !db_dir.exists() {
        println!("No packages installed.");
        return Ok(());
    }

    let mut cleared_any = false;

    loop {
        let mut all_records = get_all_installed_records(target_root)?;
        let mut required_deps = HashSet::new();

        for entry in fs::read_dir(&db_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                if path.file_name().and_then(|s| s.to_str()) == Some(".pkgd.lock") {
                    continue;
                }

                let file = File::open(&path)?;
                if let Ok(record) = serde_json::from_reader::<_, LocalPackageRecord>(file) {
                    all_records.push(record.clone());
                    
                    if let Some(deps) = &record.manifest.dependencies {
                        for dep in deps {
                            let dep_name = if let Some(idx) = dep.find('@') {
                                &dep[..idx]
                            } else {
                                dep
                            };
                            required_deps.insert(dep_name.to_string());
                        }
                    }
                }
            }
        }

        for record in &all_records {
            if let Some(deps) = &record.manifest.dependencies {
                for dep in deps {
                    let (dep_name, _) = parse_identifier(dep);
                    required_deps.insert(dep_name.to_string());
                }
            }
        }
        
        let mut orphan_to_remove = None;
        for record in &all_records {
            if record.installed_as_dependency && !required_deps.contains(&record.manifest.name) {
                orphan_to_remove = Some(record.manifest.name.clone());
                break;
            }
        }
    }

    if cleared_any {
        println!("Autoremove complete. Unused dependencies successfully purged from the file system.");
    } else {
        println!("No unused dependencies found on the system.");
    }

    Ok(())
}
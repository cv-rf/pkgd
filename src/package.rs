use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::path::Path;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use tar::Archive;

const REGISTRY_URL: &str = "http://192.168.137.1:9999";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PackageManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub checksum: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalPackageRecord {
    pub manifest: PackageManifest,
    pub files: Vec<String>,
}

pub fn download_and_install_package(package_name: &str, target_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let api_url = format!("{}/api/packages/{}", REGISTRY_URL, package_name);
    println!("Fetching manifest from: {}", api_url);

    let response = reqwest::blocking::get(&api_url)?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(format!("Package '{}' not found in remote registry.", package_name).into());
    }

    let manifest: PackageManifest = response.json()?;
    println!("Found remote package: {} ({})", manifest.name, manifest.version);

    let tarball_filename = format!("{}-{}.tar.gz", manifest.name, manifest.version);
    let download_url = format!("{}/download/{}", REGISTRY_URL, tarball_filename);
    println!("Downloading tarball from: {}", download_url);

    let mut tarball_response = reqwest::blocking::get(&download_url)?;
    if !tarball_response.status().is_success() {
        return Err("Failed to download tarball from registry server.".into());
    }

    let tmp_dir = std::env::temp_dir();
    let tmp_archive_path = tmp_dir.join(&tarball_filename);
    let mut tmp_file = File::create(&tmp_archive_path)?;

    tarball_response.copy_to(&mut tmp_file)?;

    println!("Download complete. Handing off to local installation pipeline...");

    install_package(&tmp_archive_path, target_root)?;

    let _ = fs::remove_file(tmp_archive_path);

    Ok(())
}

pub fn install_package(archive_path: &Path, target_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(archive_path)?;
    let tar_gz = GzDecoder::new(file);
    let mut archive = Archive::new(tar_gz);

    let mut manifest: Option<PackageManifest> = None;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        if path.to_str() == Some("manifest.json") {
            manifest = Some(serde_json::from_reader(&mut entry)?);
            break;
        }
    }

    let manifest = match manifest {
        Some(m) => m,
        None => return Err("Failed to find manifest.json in package archive".into()),
    };

    println!("Found package: {} ({})", manifest.name, manifest.version);

    let file = File::open(archive_path)?;
    let tar_gz = GzDecoder::new(file);
    let mut archive = Archive::new(tar_gz);

    let mut installed_files = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();

        if path.to_str() != Some("manifest.json") {
            let dest_path = target_root.join(&path);

            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            entry.unpack(&dest_path)?;
            println!("Extracted: {:?}", dest_path);

            if let Some(path_str) = path.to_str() {
                installed_files.push(path_str.to_string());
            }
        }
    }

    let record = LocalPackageRecord {
        manifest: manifest.clone(),
        files: installed_files,
    };

    let db_dir = target_root.join("var/lib/pkgd/installed");
    std::fs::create_dir_all(&db_dir)?;

    let db_file_path = db_dir.join(format!("{}.json", record.manifest.name));
    let db_file = File::create(db_file_path)?;
    serde_json::to_writer_pretty(db_file, &record)?;

    println!("Successfully registered {} in database.", record.manifest.name);
    Ok(())
}

pub fn list_packages(target_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let db_dir = target_root.join("var/lib/pkgd/installed");

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

            println!("{:<20} {:<10} {}", record.manifest.name, record.manifest.version, record.manifest.description);
        }
    }

    Ok(())
}

pub fn remove_package(package_name: &str, target_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let db_file_path = target_root.join(format!("var/lib/pkgd/installed/{}.json", package_name));

    if !db_file_path.exists() {
        return Err(format!("Package '{}' is not installed.", package_name).into());
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
    println!("Successfully removed {} from database.", package_name);

    Ok(())
}

pub fn publish_package(source_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cred_path = get_credentials_path()?;
    if !cred_path.exists() {
        return Err("Not logged in. Please run `pkgd login <token>` first.".into());
    }

    let token = fs::read_to_string(&cred_path)?;
    let auth_header = format!("Bearer {}", token.trim());

    let manifest_path = source_dir.join("manifest.json");
    if !manifest_path.exists() {
        return Err("manifest.json not found in the source directory.".into());
    }

    let manifest_str = fs::read_to_string(&manifest_path)?;
    let manifest: PackageManifest = serde_json::from_str(&manifest_str)?;

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

    let part_manifest = reqwest::blocking::multipart::Part::text(manifest_str);
    let part_tarball = reqwest::blocking::multipart::Part::bytes(tarball_bytes)
        .file_name(tarball_name)
        .mime_str("application/gzip")?;

    let form = reqwest::blocking::multipart::Form::new()
        .part("manifest", part_manifest)
        .part("tarball", part_tarball);

    let client = reqwest::blocking::Client::new();
    let res = client.post(format!("{}/api/publish", REGISTRY_URL))
        .header("Authorization", auth_header)
        .multipart(form)
        .send()?;

    if res.status().is_success() {
        println!("Package published successfully!");
    } else if res.status() == reqwest::StatusCode::UNAUTHORIZED {
        println!("Unauthorized! Invalid API token.");
    } else {
        println!("Failed to publish package. Server responded with: {}", res.status());
    }

    let _ = fs::remove_file(tmp_tar_path);

    Ok(())
}

fn get_credentials_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = std::env::var("HOME").map_err(|_| "Could not find HOME directory. Are you on Linux/macOS?")?;
    Ok(Path::new(&home).join(".pkgd").join("credentials"))
}

pub fn login(token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cred_path = get_credentials_path();

    if let Some(parent) = cred_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&cred_path, token.trm())?;

    println!("Logged in successfully. Token saved to {:?}", cred_path);
    Ok(())
}
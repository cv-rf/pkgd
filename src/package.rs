use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::path::Path;
use flate2::read::GzDecoder;
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

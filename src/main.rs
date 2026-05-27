mod package;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pkgd")]
#[command(about = "A simple custom Linux package manager made in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Install {
        package_path: PathBuf,
    },
    Remove {
        package_name: String,
    },
    List,
    Publish {
        source_dir: PathBuf,
    },
    Login {
        token: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let target_root = PathBuf::from("/tmp/pkgd_root");

    match &cli.command {
        Commands::Install { package_path } => {
            println!("Installing package from: {:?}", package_path);
            if package_path.extension().and_then(|s| s.to_str()) == Some("gz") && package_path.exists() {
                println!("Installing from local file: {:?}", package_path);
                if let Err(e) = package::install_package(package_path, &target_root) {
                    eprintln!("Error during installation: {}", e);
                }
            } else {
                let package_name = package_path.to_str().unwrap();
                println!("Searching remote registry for: {}", package_name);
                if let Err(e) = package::download_and_install_package(package_name, &target_root) {
                    eprintln!("Registry Error: {}", e);
                }
            }
        }
        Commands::List => {
            println!("Listing installed packages:");
            if let Err(e) = package::list_packages(&target_root) {
                eprintln!("Error listing packages: {}", e);
            }
        }
        Commands::Remove { package_name } => {
            println!("Removing package: {}", package_name);
            if let Err(e) = package::remove_package(package_name, &target_root) {
                eprintln!("Error during removal: {}", e)
            }
        }
        Commands::Publish { source_dir } => {
            if let Err(e) = package::publish_package(&source_dir) {
                eprintln!("Publish Error: {}", e);
            }
        }
        Commands::Login { token } => {
            if let Err(e) = package::login(token) {
                eprintln!("Login Error: {}", e);
            }
        }
    }
}
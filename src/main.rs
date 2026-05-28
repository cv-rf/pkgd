mod package;

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "pkgd")]
#[command(about = "A simple custom Linux package manager made in Rust", long_about = None)]
struct Cli {
    #[arg(long, default_value = "/")]
    root: PathBuf,

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

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let target_root = cli.root;

    match &cli.command {
        Commands::Install { package_path } => {
            if !is_root() && target_root == Path::new("/") {
                return Err("You must run 'install' with sudo privileges to modify the system.".into());
            }

            let pkg_name = package_path.to_string_lossy().to_string();
            
            if pkg_name.ends_with(".tar.gz") && package_path.exists() {
                println!("Installing from local file: {:?}", package_path);
                package::install_package(&package_path, &target_root)?;
            } else {
                println!("Searching remote registry for: {}", pkg_name);
                package::download_and_install_package(&pkg_name, &target_root)?;
            }
        }
        Commands::List => {
            println!("Listing installed packages:");
            package::list_packages(&target_root)?;
        }
        Commands::Remove { package_name } => {
            if !is_root() && target_root == Path::new("/") {
                return Err("You must run 'remove' with sudo privileges to modify the system.".into());
            }

            println!("Removing package: {}", package_name);
            package::remove_package(package_name, &target_root)?;
        }
        Commands::Publish { source_dir } => {
            if is_root() {
                return Err("Do not run 'publish' with sudo. It should be run as your normal user.".into());
            }
            package::publish_package(source_dir)?;
        }
        Commands::Login { token } => {
            if is_root() {
                return Err("Do not run 'login' with sudo. It will save credentials to the wrong user profile.".into());
            }
            package::login(token)?;
        }
    }

    Ok(())
}
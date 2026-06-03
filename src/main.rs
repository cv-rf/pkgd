mod package;

use anyhow::{Result, Context, bail};
use clap::{Parser, Subcommand};
use directories::BaseDirs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "pkgd")]
#[command(version)]
#[command(about = "A simple custom Linux package manager made in Rust", long_about = None)]
struct Cli {
    /// The root directory for installation (defaults to $HOME/.local)
    #[arg(long)]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Install { package_path: PathBuf },
    Remove { package_name: String },
    List,
    Update { package_name: Option<String> },
    Publish { source_dir: PathBuf },
    Login { token: Option<String> },
    Keygen,
    Autoremove,
}

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

fn get_default_root() -> PathBuf {
    if let Some(base_dirs) = BaseDirs::new() {
        base_dirs.home_dir().join(".local")
    } else {
        PathBuf::from("/")
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let target_root = cli.root.unwrap_or_else(get_default_root);

    match &cli.command {
        Commands::Install { package_path } => {
            if !is_root() && target_root == Path::new("/") {
                bail!("You must run 'install' with sudo privileges to modify the system root.");
            }

            let _lock = package::acquire_lock(&target_root)
                .context("Failed to acquire database lock for installation.")?;

            let pkg_name = package_path.to_string_lossy().to_string();
            
            if pkg_name.ends_with(".tar.gz") && package_path.exists() {
                println!("Installing from local file: {:?}", package_path);
                package::install_package(&package_path, &target_root, false)?;
            } else {
                println!("Searching remote registry for: {}", pkg_name);
                package::download_and_install_package(&pkg_name, &target_root)?;
            }
        }
        Commands::List => {
            println!("Listing installed packages in: {:?}", target_root);
            package::list_packages(&target_root)?;
        }
        Commands::Update { package_name} => {
            if !is_root() && target_root == Path::new("/") {
                bail!("You must run 'update' with sudo privileges to modify the system root");
            }

            let _lock = package::acquire_lock(&target_root)
                .context("Failed to acquire database lock for update.")?;

            if let Some(name) = package_name {
                println!("Checking for updates for package: {} in {:?}", name, target_root);
            } else {
                println!("Checking for updates for all installed packages in {:?}", target_root);
            }

            package::update_packages(package_name.as_deref(), &target_root)?;
        }
        Commands::Remove { package_name } => {
            if !is_root() && target_root == Path::new("/") {
                bail!("You must run 'remove' with sudo privileges to modify the system root");
            }

            let _lock = package::acquire_lock(&target_root)
                .context("Failed to acquire database lock for removal.")?;

            println!("Removing package: {} from {:?}", package_name, target_root);
            package::remove_package(package_name, &target_root)?;
        }
        Commands::Publish { source_dir } => {
            if is_root() {
                bail!("Do not run 'publish' with sudo. It should be run as your normal user.");
            }
            package::publish_package(source_dir)?;
        }
        Commands::Login { token } => {
            if is_root() {
                bail!("Do not run 'login' with sudo. It will save credentials to the wrong user profile.");
            }
            package::login(token.clone())?;
        }
        Commands::Keygen => {
            if is_root() { bail!("Do not run 'keygen' with sudo."); }
            package::generate_keys()?;
        }
        Commands::Autoremove => {
            if !is_root() && target_root == Path::new("/") {
                bail!("You must run 'autoremove' with sudo privileges to modify the system root");
            }
            let _lock = package::acquire_lock(&target_root).context("Failed to acquire database lock.")?;
            package::autoremove_packages(&target_root)?;
        }
    }

    Ok(())
}
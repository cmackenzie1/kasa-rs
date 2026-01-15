mod cli;
mod handlers;
mod utils;

use clap::Parser;

use cli::{Cli, Command};
use handlers::{handle_broadcast, handle_device, handle_discover, handle_wifi};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    match cli.command {
        Command::Version => {
            println!("kasa {}", env!("CARGO_PKG_VERSION"));
            println!("kasa-core {}", kasa_core::VERSION);
        }

        Command::Discover { timeout } => {
            handle_discover(timeout).await;
        }

        Command::Device {
            target,
            port,
            timeout,
            plug,
            legacy,
            command,
        } => {
            handle_device(
                target,
                port,
                timeout,
                plug,
                legacy,
                command,
                cli.username,
                cli.password_stdin,
            )
            .await;
        }

        Command::Broadcast {
            discovery_timeout,
            timeout,
            command,
        } => {
            handle_broadcast(
                discovery_timeout,
                timeout,
                command,
                cli.username,
                cli.password_stdin,
            )
            .await;
        }

        Command::Wifi {
            host,
            port,
            timeout,
            command,
        } => {
            handle_wifi(host, port, timeout, command).await;
        }
    }
}

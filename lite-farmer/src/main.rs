use clap::Parser;
use dg_xch_clients::api::pool::DefaultPoolClient;
use dg_xch_clients::websocket::await_termination;
use lite_farmer::config::Config;
use lite_farmer::Cli;
use lite_farmer::{generate_config_from_mnemonic, run, Action};
use log::error;
use simple_logger::SimpleLogger;
use std::io::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::select;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    SimpleLogger::new().env().init().unwrap_or_default();
    match cli.action {
        Action::Run { modes } => {
            let config_path = cli
                .config
                .unwrap_or_else(|| String::from("./farmer_config.yaml"));
            let path = Path::new(&config_path);
            if path.exists() {
                match Config::try_from(path) {
                    Ok(mut config) => {
                        config.path = config_path;
                        let config_arc = Arc::new(config);
                        let run_arc = Arc::new(AtomicBool::new(true));
                        let main_arc = run_arc.clone();
                        select!(
                            main_res = run(
                                config_arc,
                                &modes,
                                main_arc,
                                Default::default(),
                                Default::default(),
                                &None,
                                Some(Arc::new(DefaultPoolClient::new())),
                            ) => {
                                if let Err(e) = main_res {
                                    error!("Main Process Exited with Error: {:?}", e);
                                }
                            },
                            _ = await_termination() => {
                                run_arc.store(false, Ordering::SeqCst);
                            }
                        )
                    }
                    Err(e) => {
                        error!("Failed to Read config file: {:?} {:?}", config_path, e);
                    }
                }
            } else {
                error!(
                    "Failed to find config file, please generate with lite-farmer init PATH: {:?}",
                    config_path
                );
            }
        }
        Action::Init {
            mnemonic,
            fullnode_host,
            fullnode_port,
            fullnode_ssl,
            network,
            launcher_id,
        } => {
            let output_path = cli
                .config
                .map(|p| PathBuf::from(p.as_str()))
                .unwrap_or_else(|| PathBuf::from("./farmer_config.yaml"));
            generate_config_from_mnemonic(
                Some(output_path),
                mnemonic,
                fullnode_host,
                fullnode_port,
                fullnode_ssl,
                network,
                None,
                launcher_id,
            )
            .await?;
        }
    }
    Ok(())
}

use clap::{Parser, Subcommand, ValueEnum};
use dg_xch_utils::clients::api::full_node::FullnodeAPI;
use dg_xch_utils::clients::rpc::full_node::FullnodeClient;
use dg_xch_utils::consensus::constants::{CONSENSUS_CONSTANTS_MAP, MAINNET};
use dg_xch_utils::types::blockchain::sized_bytes::UnsizedBytes;
use dg_xch_utils::utils::await_termination;
use dialoguer::Confirm;
use lite_farmer::config::Config;
use lite_farmer::farmer::Farmer;
use lite_farmer::harvester::Harvester;
use log::{debug, error, info};
use simple_logger::SimpleLogger;
use std::io::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

#[derive(Debug, Subcommand)]
enum Action {
    Run {
        #[arg(value_parser)]
        modes: Vec<RunMode>,
    },
    Init,
}

#[derive(Debug, Clone, PartialEq, ValueEnum)]
enum RunMode {
    Farmer,
    Harvester,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    action: Action,
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    SimpleLogger::new().env().init().unwrap_or_default();
    match cli.action {
        Action::Run { modes } => {
            let config_path = cli
                .config
                .unwrap_or_else(|| PathBuf::from("./farmer_config.yaml"));
            if config_path.exists() {
                match Config::try_from(&config_path) {
                    Ok(mut config) => {
                        config.path = config_path.to_path_buf();
                        let config = Arc::new(config);
                        let constants = CONSENSUS_CONSTANTS_MAP
                            .get(&config.selected_network)
                            .unwrap_or(&MAINNET); //Defaults to mainnet
                        debug!(
                            "Selected Network: {}, AggSig: {}",
                            &config.selected_network,
                            &UnsizedBytes::from(constants.agg_sig_me_additional_data.clone())
                        );
                        loop {
                            let run_arc = Arc::new(Mutex::new(true));
                            let (farmer_shutdown_tx, farmer_shutdown_rx) =
                                tokio::sync::mpsc::channel::<()>(16);
                            let (harvester_shutdown_tx, harvester_shutdown_rx) =
                                tokio::sync::mpsc::channel::<()>(16);
                            let config = config.clone();
                            let use_local;
                            if let Some(peer) = &config.farmer.local_full_node_peer {
                                let local_node = FullnodeClient::new(
                                    &peer.host,
                                    8555,
                                    Some(config.farmer.ssl.root_path.clone()),
                                );
                                use_local = local_node
                                    .get_blockchain_state()
                                    .await
                                    .map(|r| r.sync.synced)
                                    .unwrap_or(false);
                            } else {
                                use_local = false;
                                info!("No Synced Local Fullnode, using remote peer.");
                            }
                            let farmer_config_arc = config.clone();
                            let node_watch_config_arc = config.clone();
                            let await_run_arc = run_arc.clone();
                            let node_watch_run_arc = run_arc.clone();
                            let is_farmer = modes.contains(&RunMode::Farmer) || modes.is_empty();
                            let is_harvester =
                                modes.contains(&RunMode::Harvester) || modes.is_empty();
                            select! {
                                _ = async {
                                    let mut handles = JoinSet::new();
                                    if is_farmer && is_harvester {
                                        match Farmer::new(farmer_config_arc.as_ref().clone()).await {
                                            Ok(farmer) => {
                                                handles.spawn(async move {
                                                    farmer.run(use_local, farmer_shutdown_rx).await;
                                                });
                                            }
                                            Err(e) => {
                                                return Err(e);
                                            }
                                        }
                                        handles.spawn(async move {
                                            Harvester::new(farmer_config_arc.clone()).run(harvester_shutdown_rx).await;
                                        });
                                    } else if is_farmer {
                                        match Farmer::new(farmer_config_arc.as_ref().clone()).await {
                                            Ok(farmer) => {
                                                handles.spawn(async move {
                                                    farmer.run(use_local, farmer_shutdown_rx).await;
                                                });
                                            }
                                            Err(e) => {
                                                return Err(e);
                                            }
                                        }
                                    } else if is_harvester {
                                        handles.spawn(async move {
                                            Harvester::new(config.clone()).run(harvester_shutdown_rx).await;
                                        });
                                    }
                                    while handles.join_next().await.is_some() {}
                                    Ok(())
                                } => {}
                                _ = await_termination() => {
                                    harvester_shutdown_tx.send(()).await.unwrap_or_default();
                                    farmer_shutdown_tx.send(()).await.unwrap_or_default();
                                    *await_run_arc.lock().await = false;
                                }
                                _ = async move {
                                    let config = node_watch_config_arc.clone();
                                    let client = config.farmer.local_full_node_peer.as_ref().map(|peer| {
                                        FullnodeClient::new(
                                            &peer.host,
                                            8555,
                                            Some(config.farmer.ssl.root_path.clone()),
                                        )
                                    });
                                    loop {
                                        if use_local {
                                            tokio::time::sleep(Duration::from_secs(1)).await;
                                        } else {
                                            if is_farmer && client.is_some() {
                                                match client.as_ref().expect("Should Not Err, Checked with is_some above").get_blockchain_state().await {
                                                    Ok(r) => if r.sync.synced {
                                                        info!("Local Fullnode is synced, restarting farmer to use local Fullnode.");
                                                        break;
                                                    }
                                                    Err(e) => {
                                                        debug!("Failed to load blockchain state: {:?}", e);
                                                    }
                                                }
                                            }
                                            tokio::time::sleep(Duration::from_secs(30)).await;
                                        }
                                        if !*node_watch_run_arc.lock().await {
                                            break;
                                        }
                                    }
                                } => {
                                    harvester_shutdown_tx.send(()).await.unwrap_or_default();
                                    farmer_shutdown_tx.send(()).await.unwrap_or_default();
                                }
                            }
                            if !*run_arc.lock().await {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to find config file: {:?}", config_path);
                        debug!("{:?}", e);
                    }
                }
            } else {
                error!(
                    "Failed to find config file, please generate with lite-farmer init PATH: {:?}",
                    config_path
                );
            }
        }
        Action::Init {} => {
            let output_path = cli
                .config
                .unwrap_or_else(|| PathBuf::from("./farmer_config.yaml"));
            if output_path.exists()
                && !Confirm::new()
                    .with_prompt(format!(
                        "An existing config exists at {:?}, would you like to override it? (Y/N)",
                        output_path
                    ))
                    .interact()?
            {
                return Ok(());
            }
            let config = Config::default();
            config.save_as_yaml(Some(output_path))?;
        }
    }
    Ok(())
}

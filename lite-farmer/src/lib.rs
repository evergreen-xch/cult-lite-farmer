use crate::config::{Config, FarmingInfo, Peer, PoolWalletConfig};
use crate::farmer::{Farmer, FarmerState};
use crate::harvester::{Harvester, HarvesterState};
use blst::min_pk::SecretKey;
use clap::{Parser, Subcommand, ValueEnum};
use dg_xch_cli::commands::scrounge_for_plotnfts;
use dg_xch_clients::api::full_node::FullnodeAPI;
use dg_xch_clients::api::pool::{DefaultPoolClient, PoolClient};
use dg_xch_clients::rpc::full_node::FullnodeClient;
use dg_xch_clients::websocket::{NodeType, ServerConnection};
use dg_xch_core::blockchain::sized_bytes::Bytes48;
use dg_xch_core::consensus::constants::{ConsensusConstants, CONSENSUS_CONSTANTS_MAP, MAINNET};
use dg_xch_core::plots::PlotHeader;
use dg_xch_keys::{
    encode_puzzle_hash, key_from_mnemonic, master_sk_to_farmer_sk, master_sk_to_pool_sk,
    master_sk_to_singleton_owner_sk, master_sk_to_wallet_sk_unhardened,
};
use dg_xch_puzzles::clvm_puzzles::launcher_id_to_p2_puzzle_hash;
use dg_xch_puzzles::p2_delegated_puzzle_or_hidden_puzzle::puzzle_hash_for_pk;
use dialoguer::Confirm;
use log::{debug, error, info};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::join;
use tokio::sync::Mutex;

pub mod config;
pub mod farmer;
pub mod harvester;
pub mod utils;

fn _version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
fn _pkg_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

pub fn version() -> String {
    format!("{}: {}", _pkg_name(), _version())
}

#[test]
fn test_version() {
    println!("{}", version());
}

#[derive(Debug, Subcommand)]
pub enum Action {
    Run {
        #[arg(value_parser)]
        modes: Vec<RunMode>,
    },
    Init {
        #[arg(short, long)]
        mnemonic: String,
        #[arg(short = 'f', long)]
        fullnode_host: String,
        #[arg(short = 'p', long)]
        fullnode_port: u16,
        #[arg(short = 's', long)]
        fullnode_ssl: Option<String>,
        #[arg(short = 'n', long)]
        network: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, ValueEnum)]
pub enum RunMode {
    Farmer,
    Harvester,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub action: Action,
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<String>,
}

pub struct State {
    pub headers: Arc<Mutex<HashMap<PathBuf, PlotHeader>>>,
    pub plot_keys: Arc<Mutex<HashMap<PathBuf, SecretKey>>>,
    pub constants: Arc<ConsensusConstants>,
}

pub struct SocketPeer {
    node_type: Option<NodeType>,
    websocket: Arc<Mutex<ServerConnection>>,
}

pub async fn run<T: PoolClient + Sized + Sync + Send + 'static>(
    config: Arc<Config>,
    modes: &[RunMode],
    run_arc: Arc<AtomicBool>,
    shared_farmer_state: Arc<Mutex<FarmerState>>,
    shared_harvester_state: Arc<Mutex<HarvesterState>>,
    additional_headers: &Option<HashMap<String, String>>,
    pool_client: Option<Arc<T>>,
) -> Result<(), Error> {
    let constants = CONSENSUS_CONSTANTS_MAP
        .get(&config.selected_network)
        .unwrap_or(&MAINNET); //Defaults to mainnet
    info!(
        "Selected Network: {}, AggSig: {}",
        &config.selected_network,
        hex::encode(constants.agg_sig_me_additional_data.clone())
    );
    loop {
        let config = config.clone();
        let use_local;
        if let Some(peer) = &config.farmer.local_full_node_peer {
            let local_node = FullnodeClient::new(
                &peer.host,
                8555,
                Some(config.farmer.ssl.root_path.clone()),
                additional_headers,
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
        let is_farmer = modes.contains(&RunMode::Farmer) || modes.is_empty();
        let is_harvester = modes.contains(&RunMode::Harvester) || modes.is_empty();
        let shared_farmer_state = shared_farmer_state.clone();
        let shared_harvester_state = shared_harvester_state.clone();
        let farmer_headers = additional_headers.clone();
        let harvester_headers = additional_headers.clone();
        let side_task_headers = additional_headers.clone();
        let pool_client = pool_client.clone();
        let crash_arc = run_arc.clone();
        let harvester_shutdown = run_arc.clone();
        let farmer_shutdown = run_arc.clone();
        let main_handle = tokio::spawn(async move {
            if is_farmer && is_harvester {
                match Farmer::new(farmer_config_arc.as_ref().clone()).await {
                    Ok(farmer) => {
                        let farmer_handle = tokio::spawn(async move {
                            if let Some(s) = pool_client {
                                farmer
                                    .run(
                                        use_local,
                                        farmer_shutdown,
                                        shared_farmer_state.clone(),
                                        &farmer_headers,
                                        s.clone(),
                                    )
                                    .await
                            } else {
                                farmer
                                    .run(
                                        use_local,
                                        farmer_shutdown,
                                        shared_farmer_state.clone(),
                                        &farmer_headers,
                                        Arc::new(DefaultPoolClient::new()),
                                    )
                                    .await
                            }
                        });
                        let harvester_handle = tokio::spawn(async move {
                            Harvester::new(farmer_config_arc.clone())
                                .run(
                                    harvester_shutdown,
                                    shared_harvester_state.clone(),
                                    &harvester_headers,
                                )
                                .await
                        });
                        match join!(farmer_handle, harvester_handle) {
                            (Ok(Ok(_)), Ok(Ok(_))) => {
                                info!("Farmer and Harvested Clean Exit");
                            }
                            (Err(e), _) => {
                                error!("Farmer Join Error: {:?}", e);
                            }
                            (_, Err(e)) => {
                                error!("Harvester Join Error: {:?}", e);
                            }
                            (Ok(Err(e)), _) => {
                                error!("Farmer Exit Error: {:?}", e);
                            }
                            (_, Ok(Err(e))) => {
                                error!("Harvester Exit Error: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to start farmer: {:?}", e);
                        return Err(e);
                    }
                };
            } else if is_farmer {
                match Farmer::new(farmer_config_arc.as_ref().clone()).await {
                    Ok(farmer) => {
                        let pool_client = pool_client.clone();
                        let farmer_handle = tokio::spawn(async move {
                            if let Some(s) = pool_client {
                                farmer
                                    .run(
                                        use_local,
                                        farmer_shutdown,
                                        shared_farmer_state.clone(),
                                        &farmer_headers,
                                        s.clone(),
                                    )
                                    .await
                            } else {
                                farmer
                                    .run(
                                        use_local,
                                        farmer_shutdown,
                                        shared_farmer_state.clone(),
                                        &farmer_headers,
                                        Arc::new(DefaultPoolClient::new()),
                                    )
                                    .await
                            }
                        });
                        let result = farmer_handle.await;
                        if let Err(e) = &result {
                            error!("Farmer Join Error: {:?}", e);
                        } else if let Ok(Err(e)) = &result {
                            error!("Farmer Handle Error: {:?}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to start farmer: {:?}", e);
                        return Err(e);
                    }
                }
            } else if is_harvester {
                let harvester_handle = tokio::spawn(async move {
                    Harvester::new(config.clone())
                        .run(
                            harvester_shutdown,
                            shared_harvester_state.clone(),
                            &harvester_headers,
                        )
                        .await
                });
                let result = harvester_handle.await;
                if let Err(e) = &result {
                    error!("Harvester Join Error: {:?}", e);
                } else if let Ok(Err(e)) = &result {
                    error!("Harvester Handle Error: {:?}", e);
                }
            }
            crash_arc.store(false, Ordering::Relaxed);
            Ok(())
        });
        let config = node_watch_config_arc.clone();
        let client = config.farmer.local_full_node_peer.as_ref().map(|peer| {
            FullnodeClient::new(
                &peer.host,
                8555,
                Some(config.farmer.ssl.root_path.clone()),
                &side_task_headers,
            )
        });
        loop {
            if use_local {
                tokio::time::sleep(Duration::from_secs(1)).await;
            } else if is_farmer {
                if let Some(c) = client.as_ref() {
                    match c.get_blockchain_state().await {
                        Ok(r) => {
                            if r.sync.synced {
                                info!("Local Fullnode is synced, restarting farmer to use local Fullnode.");
                                break;
                            } else {
                                info!("Local Fullnode is not synced");
                                tokio::time::sleep(Duration::from_secs(5)).await;
                            }
                        }
                        Err(e) => {
                            debug!("Failed to load blockchain state: {:?}", e);
                        }
                    }
                } else {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            } else {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            if !run_arc.load(Ordering::Relaxed) {
                break;
            }
        }
        run_arc.store(false, Ordering::Relaxed);
        match main_handle.await {
            Ok(res) => {
                if let Err(e) = res {
                    error!("Run Exited with Error: {:?}", e);
                }
            }
            Err(e) => {
                error!("Failed to join main run thread: {:?}", e);
            }
        }
        if !run_arc.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Ok(())
}

pub async fn generate_config_from_mnemonic(
    output_path: Option<PathBuf>,
    mnemonic: String,
    fullnode_host: String,
    fullnode_port: u16,
    fullnode_ssl: Option<String>,
    network: Option<String>,
    additional_headers: Option<HashMap<String, String>>,
) -> Result<Config, Error> {
    if let Some(op) = &output_path {
        if op.exists()
            && !Confirm::new()
                .with_prompt(format!(
                    "An existing config exists at {:?}, would you like to override it? (Y/N)",
                    op
                ))
                .interact()?
        {
            return Err(Error::new(ErrorKind::Interrupted, "User Canceled"));
        }
    }
    let mut config = Config::default();
    let (network, constants): (String, &ConsensusConstants) = network
        .map(|v| {
            if let Some(c) = CONSENSUS_CONSTANTS_MAP.get(&v) {
                (v, c)
            } else {
                ("mainnet".to_string(), &*MAINNET)
            }
        })
        .unwrap_or(("mainnet".to_string(), &*MAINNET));
    config.selected_network = network;
    let master_key = key_from_mnemonic(&mnemonic)?;
    match &fullnode_ssl {
        None => {
            config.farmer.remote_full_node_peer.host = fullnode_host.clone();
            config.farmer.remote_full_node_peer.port = if fullnode_port == 8555 {
                8444
            } else {
                fullnode_port
            };
        }
        Some(root_path) => {
            config.farmer.local_full_node_peer = Some(Peer {
                host: fullnode_host.clone(),
                port: if fullnode_port == 8555 {
                    8444
                } else {
                    fullnode_port
                },
            });
            config.farmer.ssl.root_path = root_path.clone();
            config.harvester.ssl.root_path = root_path.clone();
        }
    }
    let client = FullnodeClient::new(
        &fullnode_host,
        fullnode_port,
        fullnode_ssl,
        &additional_headers,
    );
    let mut puzzle_hashes = vec![];
    for index in 0..100 {
        let wallet_sk = master_sk_to_wallet_sk_unhardened(&master_key, index).map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to parse Wallet SK: {:?}", e),
            )
        })?;
        let ph = puzzle_hash_for_pk(&wallet_sk.sk_to_pk().to_bytes().into())?;
        puzzle_hashes.push(ph);
    }
    config.farmer.xch_target_address =
        encode_puzzle_hash(&puzzle_hashes[0], &constants.bech32_prefix)?;
    let plotnfs = scrounge_for_plotnfts(&client, &puzzle_hashes).await?;
    for plot_nft in plotnfs {
        config.pool_info.push(PoolWalletConfig {
            launcher_id: plot_nft.launcher_id,
            pool_url: plot_nft.pool_state.pool_url,
            target_puzzle_hash: plot_nft.pool_state.target_puzzle_hash,
            p2_singleton_puzzle_hash: launcher_id_to_p2_puzzle_hash(
                &plot_nft.launcher_id,
                plot_nft.delay_time as u64,
                &plot_nft.delay_puzzle_hash,
            )?,
            owner_public_key: plot_nft.pool_state.owner_pubkey,
        });
        let mut owner_key = None;
        for i in 0..21 {
            let key = master_sk_to_singleton_owner_sk(&master_key, i).unwrap();
            let pub_key: Bytes48 = key.sk_to_pk().to_bytes().into();
            if pub_key == plot_nft.pool_state.owner_pubkey {
                owner_key = Some(hex::encode(key.to_bytes()));
                break;
            }
        }
        if let Some(info) = config.farmer.farming_info.iter_mut().find(|f| {
            if let Some(l) = &f.launcher_id {
                *l == plot_nft.launcher_id.to_string()
            } else {
                false
            }
        }) {
            info.farmer_secret_key = hex::encode(master_sk_to_farmer_sk(&master_key)?.to_bytes());
            info.launcher_id = Some(plot_nft.launcher_id.to_string());
            info.owner_secret_key = owner_key;
            info.pool_secret_key = Some(hex::encode(master_sk_to_pool_sk(&master_key)?.to_bytes()));
        } else {
            config.farmer.farming_info.push(FarmingInfo {
                farmer_secret_key: hex::encode(master_sk_to_farmer_sk(&master_key)?.to_bytes()),
                launcher_id: Some(plot_nft.launcher_id.to_string()),
                pool_secret_key: Some(hex::encode(master_sk_to_pool_sk(&master_key)?.to_bytes())),
                owner_secret_key: owner_key,
            });
        }
    }
    //add nft to config
    if let Some(op) = &output_path {
        config.save_as_yaml(Some(op))?;
    }
    Ok(config)
}

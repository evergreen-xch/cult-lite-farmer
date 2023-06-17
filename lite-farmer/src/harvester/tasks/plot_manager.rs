use crate::config::Config;
use crate::harvester::HarvesterState;
use dg_xch_core::blockchain::proof_of_space::generate_plot_public_key;
use dg_xch_core::blockchain::sized_bytes::{Bytes32, Bytes48};
use dg_xch_keys::master_sk_to_local_sk;
use dg_xch_pos::prover::DiskProver;
use dg_xch_pos::read_all_plot_headers;
use futures_util::future::join_all;
use log::{debug, error, info, trace, warn};
use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct PlotInfo {
    pub prover: DiskProver,
    pub pool_public_key: Option<Bytes48>,
    pub pool_contract_puzzle_hash: Option<Bytes32>,
    pub plot_public_key: Bytes48,
    pub file_size: u64,
    pub time_modified: u64,
}

#[derive(Debug)]
pub struct PlotManager {
    pub farmer_public_keys: Vec<Bytes48>,
    pub pool_public_keys: Vec<Bytes48>,
    pub plots_missing_keys: HashSet<PathBuf>,
    pub failed_to_open: HashSet<PathBuf>,
    pub plots: HashMap<String, Arc<PlotInfo>>,
    pub config: Arc<Config>,
}
impl PlotManager {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            farmer_public_keys: vec![],
            pool_public_keys: vec![],
            plots_missing_keys: Default::default(),
            failed_to_open: Default::default(),
            plots: Default::default(),
            config,
        }
    }
    pub fn set_public_keys(
        &mut self,
        farmer_public_keys: Vec<Bytes48>,
        pool_public_keys: Vec<Bytes48>,
    ) {
        self.farmer_public_keys = farmer_public_keys;
        self.pool_public_keys = pool_public_keys;
    }
    pub async fn load_plots(
        &mut self,
        harvester_state: Arc<Mutex<HarvesterState>>,
    ) -> Result<(), Error> {
        debug!("Started Loading Plots");
        if self.farmer_public_keys.is_empty() {
            error!("No Public Keys Available");
            return Err(Error::new(
                ErrorKind::NotFound,
                format!(
                    "Keys not available: {:?}, {:?}",
                    self.farmer_public_keys, self.pool_public_keys
                ),
            ));
        }
        let farmer_public_keys = Arc::new(self.farmer_public_keys.clone());
        let pool_public_keys = Arc::new(self.pool_public_keys.clone());
        debug!(
            "Checking Plot Directories: {:?}",
            &self.config.harvester.plot_directories
        );
        let mut all_jobs = vec![];
        let mut all_failed = vec![];
        for dir in &self.config.harvester.plot_directories {
            let plot_dir_path = Path::new(dir);
            if plot_dir_path.exists() {
                info!("Validating Plot Directory: {}", dir);
                match read_all_plot_headers(plot_dir_path) {
                    Ok((headers, failed)) => {
                        debug!(
                            "Plot Headers Processed: {}, Failed: {}",
                            headers.len(),
                            failed.len()
                        );
                        all_failed.extend(failed);
                        let jobs = headers
                            .into_iter()
                            .filter_map(|(path, header)| {
                                if let Some(key) = &header.memo.pool_public_key {
                                    if !pool_public_keys.contains(key) {
                                        debug!("Missing Pool Key for Plot: {:?}", path);
                                        self.plots_missing_keys.insert(path);
                                        return None;
                                    }
                                } else if !farmer_public_keys
                                    .contains(&header.memo.farmer_public_key)
                                {
                                    debug!("Missing Farmer Key for Plot: {:?}", path);
                                    self.plots_missing_keys.insert(path);
                                    return None;
                                }
                                Some(tokio::task::spawn_blocking(move || {
                                    trace!("{:?}", header);
                                    match DiskProver::new(&path) {
                                        Ok(prover) => {
                                            let local_master_secret =
                                                prover.header.memo.local_master_secret_key.into();
                                            let (size, modified) = path
                                                .metadata()
                                                .map(|me| {
                                                    (
                                                        me.len(),
                                                        me.modified().unwrap_or(SystemTime::now()),
                                                    )
                                                })
                                                .unwrap_or_else(|_| (0, SystemTime::now()));
                                            let local_sk =
                                                match master_sk_to_local_sk(&local_master_secret) {
                                                    Ok(key) => key,
                                                    Err(e) => {
                                                        error!(
                                                            "Failed to load local secret key: {:?}",
                                                            e
                                                        );
                                                        return Err(path);
                                                    }
                                                };
                                            match generate_plot_public_key(
                                                &local_sk.sk_to_pk(),
                                                &prover.header.memo.farmer_public_key.into(),
                                                prover
                                                    .header
                                                    .memo
                                                    .pool_contract_puzzle_hash
                                                    .is_some(),
                                            ) {
                                                Ok(plot_public_key) => Ok((
                                                    path.file_name()
                                                        .map(|s| s.to_str().unwrap_or_default())
                                                        .unwrap_or_default()
                                                        .to_string(),
                                                    PlotInfo {
                                                        prover,
                                                        pool_public_key: header
                                                            .memo
                                                            .pool_public_key,
                                                        pool_contract_puzzle_hash: header
                                                            .memo
                                                            .pool_contract_puzzle_hash,
                                                        plot_public_key: plot_public_key
                                                            .to_bytes()
                                                            .into(),
                                                        file_size: size,
                                                        time_modified: modified
                                                            .duration_since(SystemTime::UNIX_EPOCH)
                                                            .map(|d| d.as_secs())
                                                            .unwrap_or_default(),
                                                    },
                                                )),
                                                Err(e) => {
                                                    error!(
                                                        "Failed to create plot public key: {:?}",
                                                        e
                                                    );
                                                    Err(path)
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to create disk prover: {:?}", e);
                                            Err(path)
                                        }
                                    }
                                }))
                            })
                            .collect::<Vec<JoinHandle<Result<(String, PlotInfo), PathBuf>>>>();
                        all_jobs.extend(jobs);
                    }
                    Err(e) => {
                        error!("Failed to validate plot dir: {}, {:?}", dir, e);
                    }
                }
            } else {
                warn!("Invalid Plot Directory: {}", dir);
            }
        }
        let mut plots: HashMap<String, Arc<PlotInfo>> = Default::default();
        for results in join_all(&mut all_jobs).await {
            match results {
                Ok(plot_res) => match plot_res {
                    Ok((k, v)) => {
                        plots.insert(k, Arc::new(v));
                    }
                    Err(e) => {
                        error!("Failed to read plot: {:?}", e);
                        all_failed.push(e);
                    }
                },
                Err(e) => {
                    error!("Join Error for Plot Read Thread: {:?}", e);
                }
            }
        }
        let og_count = plots
            .iter()
            .filter(|f| f.1.pool_public_key.is_some())
            .count();
        let pool_count = plots
            .iter()
            .filter(|f| f.1.pool_contract_puzzle_hash.is_some())
            .count();

        info!(
            "Loaded {} og plots and {} pooling plots, failed to load {}, missing keys for {}",
            og_count,
            pool_count,
            all_failed.len(),
            self.plots_missing_keys.len()
        );
        self.failed_to_open.extend(all_failed);
        self.plots.extend(plots.into_iter());
        let mut state = harvester_state.lock().await;
        state.nft_plot_count = pool_count;
        state.og_plot_count = og_count;
        state.invalid_plot_count = self.failed_to_open.len();
        state.plot_space = self.plots.values().map(|i| i.file_size).sum();
        info!("Plots Found: {}", self.plots.keys().len());
        Ok(())
    }
}

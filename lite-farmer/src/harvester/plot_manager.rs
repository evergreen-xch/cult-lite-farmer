use crate::config::Config;
use dg_xch_utils::keys::master_sk_to_local_sk;
use dg_xch_utils::plots::read_all_plot_headers;
use dg_xch_utils::proof_of_space::prover::DiskProver;
use dg_xch_utils::types::blockchain::proof_of_space::generate_plot_public_key;
use dg_xch_utils::types::blockchain::sized_bytes::{Bytes32, Bytes48};
use futures_util::future::join_all;
use log::{debug, error, info, trace, warn};
use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct PlotInfo {
    pub prover: DiskProver,
    pub pool_public_key: Option<Bytes48>,
    pub pool_contract_puzzle_hash: Option<Bytes32>,
    pub plot_public_key: Bytes48,
    pub file_size: usize,
    pub time_modified: usize,
}

#[derive(Debug)]
pub struct PlotManager {
    pub farmer_public_keys: Vec<Bytes48>,
    pub pool_public_keys: Vec<Bytes48>,
    pub plots_missing_keys: HashSet<PathBuf>,
    pub failed_to_open: HashSet<PathBuf>,
    pub plots: HashMap<String, PlotInfo>,
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
    pub async fn load_plots(&mut self) -> Result<(), Error> {
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
        for dir in &self.config.harvester.plot_directories {
            let plot_dir_path = Path::new(dir);
            if plot_dir_path.exists() {
                info!("Validating Plot Directory: {}", dir);
                match read_all_plot_headers(plot_dir_path) {
                    Ok((headers, failed)) => {
                        let plots: Arc<Mutex<HashMap<String, PlotInfo>>> = Default::default();
                        debug!(
                            "Plot Headers Processed: {}, Failed: {}",
                            headers.len(),
                            failed.len()
                        );
                        let failed: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(failed));
                        let mut jobs = headers
                            .into_iter()
                            .filter_map(|(path, header)| {
                                if let Some(key) = &header.memo.pool_public_key {
                                    if !pool_public_keys.contains(key) {
                                        warn!("Missing Pool Key for Plot: {:?}", path);
                                        self.plots_missing_keys.insert(path.to_path_buf());
                                        return None;
                                    }
                                } else if !farmer_public_keys.contains(&header.memo.farmer_public_key) {
                                    warn!("Missing Farmer Key for Plot: {:?}", path);
                                    self.plots_missing_keys.insert(path.to_path_buf());
                                    return None;
                                }
                                let plots_arc = plots.clone();
                                let failed_arc = failed.clone();
                                Some(tokio::spawn(async move {
                                    trace!("{:?}", header);
                                    match DiskProver::new(&path) {
                                        Ok(prover) => {
                                            let local_master_secret = prover
                                                .header
                                                .memo
                                                .local_master_secret_key
                                                .clone()
                                                .into();
                                            let local_sk = match master_sk_to_local_sk(
                                                &local_master_secret,
                                            ) {
                                                Ok(key) => key,
                                                Err(e) => {
                                                    error!("Failed to load local secret key: {:?}", e);
                                                    failed_arc.lock().await.push(path);
                                                    return;
                                                }
                                            };
                                            match generate_plot_public_key(
                                                &local_sk.sk_to_pk(),
                                                &prover
                                                        .header
                                                        .memo
                                                        .farmer_public_key
                                                        .clone()
                                                        .into(),
                                                prover
                                                    .header
                                                    .memo
                                                    .pool_contract_puzzle_hash
                                                    .is_some(),
                                            ) {
                                                Ok(plot_public_key) => {
                                                    plots_arc.lock().await.insert(
                                                        path.file_name()
                                                            .map(|s| {
                                                                s.to_str().unwrap_or_default()
                                                            })
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
                                                            file_size: 0,
                                                            time_modified: 0,
                                                        },
                                                    );
                                                }
                                                Err(e) => {
                                                    error!("Failed to create plot public key: {:?}", e);
                                                    failed_arc.lock().await.push(path);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to create disk prover: {:?}", e);
                                            failed_arc.lock().await.push(path);
                                        }
                                    }
                                }))
                            })
                            .collect::<Vec<JoinHandle<()>>>();
                        let _ = join_all(&mut jobs).await;
                        let failed_to_open = Arc::try_unwrap(failed)
                            .map_err(|e| {
                                Error::new(
                                    ErrorKind::InvalidInput,
                                    format!("Failed to extract value from Arc: {:?}", e),
                                )
                            })?
                            .into_inner();
                        let plots = Arc::try_unwrap(plots)
                            .map_err(|e| {
                                Error::new(
                                    ErrorKind::InvalidInput,
                                    format!("Failed to extract value from Arc: {:?}", e),
                                )
                            })?
                            .into_inner();
                        let og_count = plots
                            .iter()
                            .filter(|f| f.1.pool_public_key.is_some())
                            .count();
                        let pool_count = plots
                            .iter()
                            .filter(|f| f.1.pool_contract_puzzle_hash.is_some())
                            .count();

                        info!("Loaded {} og plots and {} pooling plots, failed to load {}, missing keys for {}", og_count, pool_count, failed_to_open.len(), self.plots_missing_keys.len());
                        self.failed_to_open.extend(failed_to_open);
                        self.plots.extend(plots);
                    }
                    Err(e) => {
                        error!("Failed to validate plot dir: {}, {:?}", dir, e);
                    }
                }
            } else {
                warn!("Invalid Plot Directory: {}", dir);
            }
        }
        info!("Plots Found: {}", self.plots.keys().len());
        Ok(())
    }
}

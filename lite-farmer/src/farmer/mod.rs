use crate::config::{Config, PoolWalletConfig};
use crate::farmer::server::FarmerServer;
use crate::farmer::tasks::request_signed_values::RequestSignedValuesHandle;
use crate::farmer::tasks::signage_point::NewSignagePointHandle;
use crate::utils::error::RecentErrors;
use crate::SocketPeer;
use blst::min_pk::SecretKey;
use dg_xch_clients::api::pool::PoolClient;
use dg_xch_clients::protocols::farmer::NewSignagePoint;
use dg_xch_clients::protocols::pool::{
    get_current_authentication_token, AuthenticationPayload, GetFarmerRequest, GetFarmerResponse,
    PoolError, PoolErrorCode, PostFarmerPayload, PostFarmerRequest, PostFarmerResponse,
    PutFarmerPayload, PutFarmerRequest, PutFarmerResponse,
};
use dg_xch_clients::protocols::ProtocolMessageTypes;
use dg_xch_clients::websocket::farmer::FarmerClient;
use dg_xch_clients::websocket::{
    ChiaMessageFilter, ChiaMessageHandler, ClientSSLConfig, Websocket,
};
use dg_xch_core::blockchain::proof_of_space::ProofOfSpace;
use dg_xch_core::blockchain::sized_bytes::{hex_to_bytes, Bytes32, Bytes48};
use dg_xch_core::clvm::bls_bindings::{sign, verify_signature};
use dg_xch_keys::decode_puzzle_hash;
use dg_xch_serialize::hash_256;
use dg_xch_serialize::ChiaSerialize;
use futures_util::{join, TryFutureExt};
use log::{debug, error, info, warn};
use num_integer::Integer;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use uuid::Uuid;

mod server;
mod tasks;

const UPDATE_POOL_INFO_INTERVAL: u64 = 600;
const UPDATE_POOL_INFO_FAILURE_RETRY_INTERVAL: u64 = 120;
const UPDATE_POOL_FARMER_INFO_INTERVAL: u64 = 300;

#[derive(Debug, Clone)]
pub struct FarmerPoolState {
    points_found_since_start: u64,
    points_found_24h: Vec<(Instant, u64)>,
    points_acknowledged_since_start: u64,
    points_acknowledged_24h: Vec<(Instant, u64)>,
    next_farmer_update: Instant,
    next_pool_info_update: Instant,
    current_points: u64,
    current_difficulty: Option<u64>,
    pool_config: Option<PoolWalletConfig>,
    pool_errors_24h: Vec<(Instant, String)>,
    authentication_token_timeout: Option<u8>,
}
impl Default for FarmerPoolState {
    fn default() -> Self {
        Self {
            points_found_since_start: 0,
            points_found_24h: vec![],
            points_acknowledged_since_start: 0,
            points_acknowledged_24h: vec![],
            next_farmer_update: Instant::now(),
            next_pool_info_update: Instant::now(),
            current_points: 0,
            current_difficulty: None,
            pool_config: None,
            pool_errors_24h: vec![],
            authentication_token_timeout: None,
        }
    }
}

#[derive(Debug)]
pub struct FarmerIdentifier {
    plot_identifier: String,
    challenge_hash: Bytes32,
    sp_hash: Bytes32,
    peer_node_id: Bytes32,
}

type ProofsMap = Arc<Mutex<HashMap<Bytes32, Vec<(String, ProofOfSpace)>>>>;

#[derive(Default)]
pub struct Farmer {
    signage_points: Arc<Mutex<HashMap<Bytes32, Vec<NewSignagePoint>>>>,
    quality_to_identifiers: Arc<Mutex<HashMap<Bytes32, FarmerIdentifier>>>,
    proofs_of_space: ProofsMap,
    cache_time: Arc<Mutex<HashMap<Bytes32, Instant>>>,
    pool_state: Arc<Mutex<HashMap<Bytes32, FarmerPoolState>>>,
    farmer_public_keys: Arc<Mutex<HashMap<Bytes48, SecretKey>>>,
    farmer_private_keys: Arc<Mutex<Vec<SecretKey>>>,
    pool_public_keys: Arc<Mutex<HashMap<Bytes48, SecretKey>>>,
    owner_secret_keys: Arc<Mutex<HashMap<Bytes48, SecretKey>>>,
    config: Arc<Mutex<Config>>,
    full_node_client: Arc<Mutex<Option<FarmerClient>>>,
    peers: Arc<Mutex<HashMap<Bytes32, SocketPeer>>>,
    _run: Arc<Mutex<bool>>,
    farmer_target: Arc<Bytes32>,
    pool_target: Arc<Bytes32>,
}

#[derive(Default, Clone)]
pub struct FarmerState {
    pub most_recent_sp: (Bytes32, u8),
    pub keys: Vec<Bytes48>,
    pub running_state: FarmerRunningState,
    pub recent_errors: RecentErrors<String>,
}

#[derive(Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, Copy, Clone)]
pub enum FarmerRunningState {
    #[default]
    Starting,
    NeedsConfig,
    Running,
    Stopped,
    Failed,
    PendingReload,
}

impl Farmer {
    pub async fn new(config: Config) -> Result<Self, Error> {
        let farmer_target_encoded = &config.farmer.xch_target_address;
        let farmer_target = decode_puzzle_hash(farmer_target_encoded)?;
        let pool_target = decode_puzzle_hash(farmer_target_encoded)?;
        let mut farmer = Self {
            config: Arc::new(Mutex::new(config)),
            farmer_target: Arc::new(farmer_target),
            pool_target: Arc::new(pool_target),
            ..Default::default()
        };
        farmer.load_keys().await;
        Ok(farmer)
    }

    async fn load_keys(&mut self) {
        for farmer_info in self.config.lock().await.farmer.farming_info.iter() {
            if let Ok(bytes) = hex_to_bytes(&farmer_info.farmer_secret_key) {
                if let Ok(sec_key) = SecretKey::from_bytes(&bytes) {
                    self.farmer_public_keys
                        .lock()
                        .await
                        .insert(sec_key.sk_to_pk().to_bytes().into(), sec_key.clone());
                    self.farmer_private_keys.lock().await.push(sec_key)
                }
            }
            if let Some(key) = &farmer_info.pool_secret_key {
                if let Ok(bytes) = hex_to_bytes(key) {
                    if let Ok(sec_key) = SecretKey::from_bytes(&bytes) {
                        self.pool_public_keys
                            .lock()
                            .await
                            .insert(sec_key.sk_to_pk().to_bytes().into(), sec_key.clone());
                    }
                }
            }
            if let Some(key) = &farmer_info.owner_secret_key {
                if let Ok(bytes) = hex_to_bytes(key) {
                    if let Ok(sec_key) = SecretKey::from_bytes(&bytes) {
                        self.owner_secret_keys
                            .lock()
                            .await
                            .insert(sec_key.sk_to_pk().to_bytes().into(), sec_key.clone());
                    }
                }
            }
        }
        debug!("Done Loading Keys");
    }

    pub async fn run<T: PoolClient + Sized + Sync + Send + 'static>(
        self,
        use_local: bool,
        shutdown_receiver: Arc<AtomicBool>,
        farmer_state: Arc<Mutex<FarmerState>>,
        additional_headers: &Option<HashMap<String, String>>,
        client: Arc<T>,
    ) -> Result<(), Error> {
        let farmer_arc = Arc::new(self);
        let server = FarmerServer::new(farmer_arc.clone(), farmer_state.clone());
        let server_run = shutdown_receiver.clone();
        let client_run = shutdown_receiver.clone();
        let server_client = client.clone();
        let server_farmer_state = farmer_state.clone();
        let server_handle = tokio::spawn(async move {
            let farmer_state = server_farmer_state.clone();
            let retry_run = server_run.clone();
            let mut failed = 0;
            let mut res = Err(Error::new(
                ErrorKind::ConnectionAborted,
                "Farmer Server Never Connected",
            ));
            loop {
                if !retry_run.load(Ordering::Relaxed) {
                    break;
                }
                res = server
                    .start(server_run.clone(), server_client.clone())
                    .await;
                if let Err(e) = &res {
                    error!("Error Starting Farmer Server: {:?}", e);
                    {
                        farmer_state
                            .lock()
                            .await
                            .recent_errors
                            .add(format!("Error Starting Farmer Server: {:?}", e));
                    }
                    failed += 1;
                    if failed >= 5 {
                        error!(
                            "Error Starting Farmer Server, Too Many Retries({failed}): {:?}",
                            e
                        );
                        {
                            farmer_state.lock().await.recent_errors.add(format!(
                                "Error Starting Farmer Server, Too Many Retries({failed}): {:?}",
                                e
                            ));
                        }
                        retry_run.store(false, Ordering::Relaxed);
                    } else {
                        warn!(
                            "Failed to Start Farmer Server, Retry Attempts({failed}): {:?}",
                            e
                        );
                        {
                            farmer_state.lock().await.recent_errors.add(format!(
                                "Failed to Start Farmer Server, Retry Attempts({failed}): {:?}",
                                e
                            ));
                        }
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                } else {
                    info!("Farmer Server Stopped");
                }
            }
            res
        });
        let pool_update_farmer_arc = farmer_arc.clone();
        let pool_state_client = client.clone();
        let pool_state_run = shutdown_receiver.clone();
        let pool_state_handle: JoinHandle<Result<(), Error>> = tokio::spawn(async move {
            let mut last_update = Instant::now();
            let mut first = true;
            loop {
                if !pool_state_run.load(Ordering::Relaxed) {
                    break;
                }
                if first || Instant::now().duration_since(last_update).as_secs() >= 60 {
                    first = false;
                    debug!("Updating Pool State");
                    update_pool_state(pool_update_farmer_arc.clone(), pool_state_client.clone())
                        .await;
                    last_update = Instant::now();
                }
                tokio::time::sleep(Duration::from_secs(1)).await
            }
            info!("Pool Handle Stopped");
            Ok(())
        });
        'retry: loop {
            let farmer = farmer_arc.clone();
            let config = farmer.config.lock().await.clone();
            let (host, port) = if use_local && config.farmer.local_full_node_peer.is_some() {
                let peer = config
                    .farmer
                    .local_full_node_peer
                    .as_ref()
                    .expect("Should Not Happen, Checked with is_some above.");
                (peer.host.as_str(), peer.port)
            } else {
                (
                    config.farmer.remote_full_node_peer.host.as_str(),
                    config.farmer.remote_full_node_peer.port,
                )
            };
            {
                if let Some(c) = &*farmer.full_node_client.lock().await {
                    info!("Shutting Down old Farmer Client: {host}:{port}");
                    c.client.lock().await.shutdown().await.unwrap_or_default();
                }
            }
            if let (Some(public_crt), Some(public_key), Some(ca_public_crt)) = (
                &config.farmer.ssl.certs.public_crt,
                &config.farmer.ssl.certs.public_key,
                &config.farmer.ssl.ca.public_crt,
            ) {
                info!("Initializing SSL Farmer Client: {host}:{port}");
                let ssl_crt_path = format!("{}/{}", &config.farmer.ssl.root_path, public_crt);
                let ssl_key_path = format!("{}/{}", &config.farmer.ssl.root_path, public_key);
                let ssl_ca_crt_path = format!("{}/{}", &config.farmer.ssl.root_path, ca_public_crt);
                let network_id = config.selected_network.as_str();
                *farmer.full_node_client.lock().await = match FarmerClient::new_ssl(
                    host,
                    port,
                    ClientSSLConfig {
                        ssl_crt_path: ssl_crt_path.as_str(),
                        ssl_key_path: ssl_key_path.as_str(),
                        ssl_ca_crt_path: ssl_ca_crt_path.as_str(),
                    },
                    network_id,
                    additional_headers,
                    client_run.clone(),
                )
                .await
                {
                    Ok(c) => Some(c),
                    Err(e) => {
                        error!(
                            "Failed to Start Farmer Client, Waiting and trying again: {:?}",
                            e
                        );
                        {
                            farmer_state.lock().await.recent_errors.add(format!(
                                "Failed to Start Farmer Client, Waiting and trying again: {:?}",
                                e
                            ));
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        if !client_run.load(Ordering::Relaxed) {
                            break;
                        }
                        continue;
                    }
                };
            } else {
                info!("Initializing Farmer Client: {host}:{port}");
                let network_id = config.selected_network.as_str();
                *farmer.full_node_client.lock().await = match FarmerClient::new(
                    host,
                    port,
                    network_id,
                    additional_headers,
                    client_run.clone(),
                )
                .await
                {
                    Ok(c) => Some(c),
                    Err(e) => {
                        error!(
                            "Failed to Start Farmer Client, Waiting and trying again: {:?}",
                            e
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        if !client_run.load(Ordering::Relaxed) {
                            break;
                        }
                        continue;
                    }
                };
            }
            if let Some(fnc) = farmer.full_node_client.lock().await.as_ref() {
                let mut client = fnc.client.lock().await;
                client.clear().await;
                let signage_handle_id = Uuid::new_v4();
                let signage_handle = Arc::new(NewSignagePointHandle {
                    id: signage_handle_id,
                    peers: farmer.peers.clone(),
                    pool_state: farmer.pool_state.clone(),
                    signage_points: farmer.signage_points.clone(),
                    farmer_state: farmer_state.clone(),
                    cache_time: Arc::new(Default::default()),
                });
                client
                    .subscribe(
                        signage_handle_id,
                        ChiaMessageHandler::new(
                            ChiaMessageFilter {
                                msg_type: Some(ProtocolMessageTypes::NewSignagePoint),
                                id: None,
                            },
                            signage_handle,
                        ),
                    )
                    .await;
                let request_signed_values_id = Uuid::new_v4();
                let request_signed_values_handle = Arc::new(RequestSignedValuesHandle {
                    id: request_signed_values_id,
                    quality_to_identifiers: farmer.quality_to_identifiers.clone(),
                    peers: farmer.peers.clone(),
                    farmer_state: farmer_state.clone(),
                });
                client
                    .subscribe(
                        request_signed_values_id,
                        ChiaMessageHandler::new(
                            ChiaMessageFilter {
                                msg_type: Some(ProtocolMessageTypes::RequestSignedValues),
                                id: None,
                            },
                            request_signed_values_handle,
                        ),
                    )
                    .await;
                info!("Farmer Client Initialized");
            } else {
                error!("Failed to Initialize Farmer");
            }
            loop {
                if let Some(client) = farmer.full_node_client.lock().await.as_ref() {
                    if client.is_closed() {
                        if !client_run.load(Ordering::Relaxed) {
                            farmer_state.lock().await.running_state = FarmerRunningState::Stopped;
                            info!("Farmer Stopping from global run");
                            break 'retry;
                        } else {
                            farmer_state.lock().await.running_state = FarmerRunningState::Failed;
                            info!("Farmer Client Closed, Reconnecting");
                            break;
                        }
                    } else {
                        farmer_state.lock().await.running_state = FarmerRunningState::Running;
                    }
                } else {
                    info!("No Farmer Client Found, Reconnecting");
                    farmer_state.lock().await.running_state = FarmerRunningState::Failed;
                    break;
                }
                let keys: Vec<Bytes48>;
                {
                    keys = farmer
                        .farmer_public_keys
                        .lock()
                        .await
                        .keys()
                        .copied()
                        .collect();
                }
                farmer_state.lock().await.keys = keys;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            if !client_run.load(Ordering::Relaxed) {
                info!("Farmer Stopping from global run");
                break 'retry;
            }
        }
        match join!(
            server_handle
                .map_err(|e| { Error::new(ErrorKind::Other, format!("Join Error:{:?}", e)) }),
            pool_state_handle
                .map_err(|e| { Error::new(ErrorKind::Other, format!("Join Error:{:?}", e)) })
        ) {
            (Ok(_), Ok(_)) => {
                info!("Farmer Server Shutting Down");
                shutdown_receiver.store(false, Ordering::Relaxed);
                Ok(())
            }
            (Ok(_), Err(e)) => {
                error!("Pool State Error farmer: {:?}", e);
                shutdown_receiver.store(false, Ordering::Relaxed);
                Err(e)
            }
            (Err(e), Ok(_)) => {
                error!("Farmer Error: {:?}", e);
                shutdown_receiver.store(false, Ordering::Relaxed);
                Err(e)
            }
            (Err(e), Err(e2)) => {
                error!("Farmer Error: {:?}", e);
                error!("Pool State Error farmer: {:?}", e2);
                shutdown_receiver.store(false, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    pub async fn get_farmer<T: PoolClient + Sized + Sync + Send>(
        &self,
        pool_config: &PoolWalletConfig,
        authentication_token_timeout: u8,
        authentication_sk: &SecretKey,
        client: Arc<T>,
    ) -> Result<GetFarmerResponse, PoolError> {
        let authentication_token = get_current_authentication_token(authentication_token_timeout);
        let msg = AuthenticationPayload {
            method_name: "get_farmer".to_string(),
            launcher_id: pool_config.launcher_id,
            target_puzzle_hash: pool_config.target_puzzle_hash,
            authentication_token,
        }
        .to_bytes();
        let to_sign = hash_256(&msg);
        let signature = sign(authentication_sk, &to_sign);
        if !verify_signature(&authentication_sk.sk_to_pk(), &to_sign, &signature) {
            error!("Farmer GET Failed to Validate Signature");
            return Err(PoolError {
                error_code: PoolErrorCode::InvalidSignature as u8,
                error_message: "Local Failed to Validate Signature".to_string(),
            });
        }
        client
            .get_farmer(
                &pool_config.pool_url,
                GetFarmerRequest {
                    launcher_id: pool_config.launcher_id,
                    authentication_token,
                    signature: signature.to_bytes().into(),
                },
            )
            .await
    }

    async fn do_auth(
        &self,
        pool_config: &PoolWalletConfig,
        owner_sk: &SecretKey,
    ) -> Result<Bytes48, PoolError> {
        if owner_sk.sk_to_pk().to_bytes() != *pool_config.owner_public_key.to_sized_bytes() {
            return Err(PoolError {
                error_code: PoolErrorCode::ServerException as u8,
                error_message: "Owner Keys Mismatch".to_string(),
            });
        }
        Ok(owner_sk.sk_to_pk().to_bytes().into())
    }

    pub async fn post_farmer<T: PoolClient + Sized + Sync + Send>(
        &self,
        pool_config: &PoolWalletConfig,
        payout_instructions: &str,
        authentication_token_timeout: u8,
        owner_sk: &SecretKey,
        client: Arc<T>,
    ) -> Result<PostFarmerResponse, PoolError> {
        let payload = PostFarmerPayload {
            launcher_id: pool_config.launcher_id,
            authentication_token: get_current_authentication_token(authentication_token_timeout),
            authentication_public_key: self.do_auth(pool_config, owner_sk).await?,
            payout_instructions: parse_payout_address(payout_instructions.to_string()).map_err(
                |e| PoolError {
                    error_code: PoolErrorCode::InvalidPayoutInstructions as u8,
                    error_message: format!(
                        "Failed to Parse Payout Instructions: {}, {:?}",
                        payout_instructions, e
                    ),
                },
            )?,
            suggested_difficulty: None,
        };
        let to_sign = hash_256(payload.to_bytes());
        let signature = sign(owner_sk, &to_sign);
        if !verify_signature(&owner_sk.sk_to_pk(), &to_sign, &signature) {
            error!("Farmer POST Failed to Validate Signature");
            return Err(PoolError {
                error_code: PoolErrorCode::InvalidSignature as u8,
                error_message: "Local Failed to Validate Signature".to_string(),
            });
        }
        client
            .post_farmer(
                &pool_config.pool_url,
                PostFarmerRequest {
                    payload,
                    signature: signature.to_bytes().into(),
                },
            )
            .await
    }

    pub async fn put_farmer<T: PoolClient + Sized + Sync + Send>(
        &self,
        pool_config: &PoolWalletConfig,
        payout_instructions: &str,
        authentication_token_timeout: u8,
        owner_sk: &SecretKey,
        client: Arc<T>,
    ) -> Result<PutFarmerResponse, PoolError> {
        let authentication_public_key = self.do_auth(pool_config, owner_sk).await?;
        let payload = PutFarmerPayload {
            launcher_id: pool_config.launcher_id,
            authentication_token: get_current_authentication_token(authentication_token_timeout),
            authentication_public_key: Some(authentication_public_key),
            payout_instructions: parse_payout_address(payout_instructions.to_string()).ok(),
            suggested_difficulty: None,
        };
        let to_sign = hash_256(payload.to_bytes());
        let signature = sign(owner_sk, &to_sign);
        if !verify_signature(&owner_sk.sk_to_pk(), &to_sign, &signature) {
            error!("Local Failed to Validate Signature");
            return Err(PoolError {
                error_code: PoolErrorCode::InvalidSignature as u8,
                error_message: "Local Failed to Validate Signature".to_string(),
            });
        }
        let request = PutFarmerRequest {
            payload,
            signature: signature.to_bytes().into(),
        };
        client.put_farmer(&pool_config.pool_url, request).await
    }

    pub async fn update_pool_farmer_info<T: PoolClient + Sized + Sync + Send>(
        &self,
        pool_state: &mut FarmerPoolState,
        pool_config: &PoolWalletConfig,
        authentication_token_timeout: u8,
        authentication_sk: &SecretKey,
        client: Arc<T>,
    ) -> Result<GetFarmerResponse, PoolError> {
        let response = self
            .get_farmer(
                pool_config,
                authentication_token_timeout,
                authentication_sk,
                client,
            )
            .await?;
        pool_state.current_difficulty = Some(response.current_difficulty);
        pool_state.current_points = response.current_points;
        info!(
            "Updating Pool Difficulty: {:?} ",
            pool_state.current_difficulty
        );
        info!("Updating Current Points: {:?} ", pool_state.current_points);
        Ok(response)
    }
}

pub async fn update_pool_state<'a, T: 'a + PoolClient + Sized + Sync + Send>(
    farmer: Arc<Farmer>,
    client: Arc<T>,
) {
    let config = farmer.config.lock().await.clone();
    for pool_config in &config.pool_info {
        let owner_secret_key = farmer
            .owner_secret_keys
            .lock()
            .await
            .get(&pool_config.owner_public_key)
            .cloned();
        if let Some(owner_secret_key) = owner_secret_key {
            {
                //Lock Scope
                let state_exists = farmer
                    .pool_state
                    .lock()
                    .await
                    .get(&pool_config.p2_singleton_puzzle_hash)
                    .is_some();
                if !state_exists {
                    farmer.pool_state.lock().await.insert(
                        pool_config.p2_singleton_puzzle_hash,
                        FarmerPoolState {
                            points_found_since_start: 0,
                            points_found_24h: vec![],
                            points_acknowledged_since_start: 0,
                            points_acknowledged_24h: vec![],
                            next_farmer_update: Instant::now(),
                            next_pool_info_update: Instant::now(),
                            current_points: 0,
                            current_difficulty: None,
                            pool_config: None,
                            pool_errors_24h: vec![],
                            authentication_token_timeout: None,
                        },
                    );
                    info!("Added pool: {:?}", pool_config);
                }
            }
            let mut pool_state = farmer
                .pool_state
                .lock()
                .await
                .get_mut(&pool_config.p2_singleton_puzzle_hash)
                .cloned()
                .unwrap_or_default();
            pool_state.pool_config = Some(pool_config.clone());
            if pool_config.pool_url.is_empty() {
                continue;
            }
            if config.selected_network == "mainnet" && !pool_config.pool_url.starts_with("https") {
                error!(
                    "Pool URLs must be HTTPS on mainnet {}",
                    pool_config.pool_url
                );
                continue;
            }
            if Instant::now() >= pool_state.next_pool_info_update {
                pool_state.next_pool_info_update =
                    Instant::now() + Duration::from_secs(UPDATE_POOL_INFO_INTERVAL);
                //Makes a GET request to the pool to get the updated information
                match client.get_pool_info(&pool_config.pool_url).await {
                    Ok(pool_info) => {
                        pool_state.authentication_token_timeout =
                            Some(pool_info.authentication_token_timeout);
                        // Only update the first time from GET /pool_info, gets updated from GET /farmer later
                        if pool_state.current_difficulty.is_none() {
                            pool_state.current_difficulty = Some(pool_info.minimum_difficulty);
                        }
                    }
                    Err(e) => {
                        pool_state.next_pool_info_update = Instant::now()
                            + Duration::from_secs(UPDATE_POOL_INFO_FAILURE_RETRY_INTERVAL);
                        error!("Update Pool Info Error: {:?}", e);
                    }
                }
            } else {
                debug!("Not Ready for Update");
            }
            if Instant::now() >= pool_state.next_farmer_update {
                pool_state.next_farmer_update =
                    Instant::now() + Duration::from_secs(UPDATE_POOL_FARMER_INFO_INTERVAL);
                if let Some(authentication_token_timeout) = pool_state.authentication_token_timeout
                {
                    info!("Running Farmer Pool Update");
                    let farmer_info = match farmer
                        .update_pool_farmer_info(
                            &mut pool_state,
                            pool_config,
                            authentication_token_timeout,
                            &owner_secret_key,
                            client.clone(),
                        )
                        .await
                    {
                        Ok(resp) => Some(resp),
                        Err(e) => {
                            if e.error_code == PoolErrorCode::FarmerNotKnown as u8 {
                                warn!("Farmer Pool Not Known");
                                match farmer
                                    .post_farmer(
                                        pool_config,
                                        &config.farmer.xch_target_address,
                                        authentication_token_timeout,
                                        &owner_secret_key,
                                        client.clone(),
                                    )
                                    .await
                                {
                                    Ok(resp) => {
                                        info!(
                                            "Welcome message from {} : {}",
                                            pool_config.pool_url, resp.welcome_message
                                        );
                                    }
                                    Err(e) => {
                                        error!("Failed post farmer info. {:?}", e);
                                    }
                                }
                                match farmer
                                    .update_pool_farmer_info(
                                        &mut pool_state,
                                        pool_config,
                                        authentication_token_timeout,
                                        &owner_secret_key,
                                        client.clone(),
                                    )
                                    .await
                                {
                                    Ok(resp) => Some(resp),
                                    Err(e) => {
                                        error!(
                                            "Failed to update farmer info after POST /farmer. {:?}",
                                            e
                                        );
                                        None
                                    }
                                }
                            } else if e.error_code == PoolErrorCode::InvalidSignature as u8 {
                                warn!("Invalid Signature Detected, Updating Farmer Auth Key");
                                match farmer
                                    .put_farmer(
                                        pool_config,
                                        &config.farmer.xch_target_address,
                                        authentication_token_timeout,
                                        &owner_secret_key,
                                        client.clone(),
                                    )
                                    .await
                                {
                                    Ok(res) => {
                                        info!("Farmer Update Response: {:?}", res);
                                        farmer
                                            .update_pool_farmer_info(
                                                &mut pool_state,
                                                pool_config,
                                                authentication_token_timeout,
                                                &owner_secret_key,
                                                client.clone(),
                                            )
                                            .await
                                            .ok()
                                    }
                                    Err(e) => {
                                        error!("Failed to update farmer auth key. {:?}", e);
                                        None
                                    }
                                }
                            } else {
                                None
                            }
                        }
                    };
                    let old_instructions;
                    let payout_instructions_update_required = if let Some(info) = farmer_info {
                        if let (Ok(p1), Ok(p2)) = (
                            parse_payout_address(
                                config.farmer.xch_target_address.to_ascii_lowercase(),
                            ),
                            parse_payout_address(info.payout_instructions.to_ascii_lowercase()),
                        ) {
                            old_instructions = p2;
                            p1 != old_instructions
                        } else {
                            old_instructions = String::new();
                            false
                        }
                    } else {
                        old_instructions = String::new();
                        false
                    };
                    if payout_instructions_update_required {
                        info!(
                            "Updating Payout Address from {} : {}",
                            config.farmer.xch_target_address.to_ascii_lowercase(),
                            old_instructions
                        );
                        match &farmer
                            .owner_secret_keys
                            .lock()
                            .await
                            .get(&pool_config.owner_public_key)
                        {
                            None => {
                                error!(
                                    "Could not find Owner SK for {}",
                                    &pool_config.owner_public_key
                                );
                                continue;
                            }
                            Some(sk) => {
                                match farmer
                                    .put_farmer(
                                        pool_config,
                                        &config.farmer.xch_target_address,
                                        authentication_token_timeout,
                                        sk,
                                        client.clone(),
                                    )
                                    .await
                                {
                                    Ok(res) => {
                                        info!("Farmer Update Response: {:?}", res);
                                    }
                                    Err(e) => {
                                        error!("Failed to update farmer auth key. {:?}", e);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    warn!("No pool specific authentication_token_timeout has been set for {}, check communication with the pool.", &pool_config.p2_singleton_puzzle_hash);
                }
                //Update map
                farmer
                    .pool_state
                    .lock()
                    .await
                    .insert(pool_config.p2_singleton_puzzle_hash, pool_state);
            }
        } else {
            warn!(
                "Could not find owner sk for: {:?}",
                &pool_config.owner_public_key
            );
        }
    }
}

fn parse_payout_address(s: String) -> Result<String, Error> {
    Ok(if s.starts_with("xch") || s.starts_with("txch") {
        hex::encode(decode_puzzle_hash(&s)?)
    } else if s.len().is_even() {
        match hex_to_bytes(&s) {
            Ok(h) => hex::encode(h),
            Err(_) => s,
        }
    } else {
        s
    })
}

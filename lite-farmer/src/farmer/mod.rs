use crate::config::{Config, PoolWalletConfig};
use crate::farmer::api::{NewSignagePointHandle, RequestSignedValuesHandle};
use crate::farmer::server::FarmerServer;
use crate::Peer;
use blst::min_pk::{PublicKey, SecretKey};
use dg_xch_utils::clients::pool::PoolClient;
use dg_xch_utils::clients::protocols::farmer::NewSignagePoint;
use dg_xch_utils::clients::protocols::pool::{
    get_current_authentication_token, AuthenticationPayload, GetFarmerRequest, GetFarmerResponse,
    GetPoolInfoResponse, PoolError, PoolErrorCode, PostFarmerPayload, PostFarmerRequest,
    PostFarmerResponse, PutFarmerPayload, PutFarmerRequest, PutFarmerResponse,
};
use dg_xch_utils::clients::protocols::ProtocolMessageTypes;
use dg_xch_utils::clients::websocket::farmer::FarmerClient;
use dg_xch_utils::clients::websocket::{ChiaMessageFilter, ChiaMessageHandler, Websocket};
use dg_xch_utils::clvm::bls_bindings::sign;
use dg_xch_utils::clvm::utils::hash_256;
use dg_xch_utils::keys::decode_puzzle_hash;
use dg_xch_utils::types::blockchain::proof_of_space::ProofOfSpace;
use dg_xch_utils::types::blockchain::sized_bytes::{hex_to_bytes, Bytes32, Bytes48};
use dg_xch_utils::types::ChiaSerialize;
use futures_util::join;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::io::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use uuid::Uuid;

mod api;
mod server;

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
    auth_keys: Arc<Mutex<HashMap<Bytes32, SecretKey>>>,
    farmer_public_keys: Arc<Mutex<HashMap<Bytes48, SecretKey>>>,
    farmer_private_keys: Arc<Mutex<Vec<SecretKey>>>,
    pool_public_keys: Arc<Mutex<HashMap<Bytes48, SecretKey>>>,
    owner_secret_keys: Arc<Mutex<HashMap<Bytes48, SecretKey>>>,
    pub auth_secret_keys: Arc<Mutex<HashMap<Bytes48, SecretKey>>>,
    config: Arc<Mutex<Config>>,
    pool_client: Arc<PoolClient>,
    full_node_client: Arc<Mutex<Option<FarmerClient>>>,
    peers: Arc<Mutex<HashMap<Bytes32, Peer>>>,
    _run: Arc<Mutex<bool>>,
    farmer_target: Arc<Bytes32>,
    pool_target: Arc<Bytes32>,
}

impl Farmer {
    pub async fn new(config: Config) -> Result<Self, Error> {
        let farmer_target_encoded = &config.farmer.xch_target_address;
        let farmer_target = decode_puzzle_hash(farmer_target_encoded)?;
        let pool_target = decode_puzzle_hash(farmer_target_encoded)?;
        let mut farmer = Self {
            config: Arc::new(Mutex::new(config)),
            pool_client: Arc::new(PoolClient::new()),
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
                        if let Some(key) = &farmer_info.auth_secret_key {
                            if let Ok(bytes) = hex_to_bytes(key) {
                                if let Ok(auth_key) = SecretKey::from_bytes(&bytes) {
                                    self.auth_secret_keys.lock().await.insert(
                                        sec_key.sk_to_pk().to_bytes().into(),
                                        auth_key.clone(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        for c in &self.config.lock().await.pool_list {
            if let Ok(pub_key) = PublicKey::from_bytes(&c.owner_public_key.to_sized_bytes()) {
                if let Some(sec_key) = self
                    .auth_secret_keys
                    .lock()
                    .await
                    .get(&pub_key.to_bytes().into())
                {
                    self.auth_keys
                        .lock()
                        .await
                        .insert(c.p2_singleton_puzzle_hash.clone(), sec_key.clone());
                }
            }
        }
        debug!("Done Loading Keys");
    }

    pub async fn run(self, use_local: bool, shutdown_receiver: Receiver<()>) {
        let global_run = Arc::new(Mutex::new(true));
        let farmer_arc = Arc::new(self);
        let server = FarmerServer::new(farmer_arc.clone());
        let server_run = global_run.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server.start(server_run, shutdown_receiver).await;
        });
        let pool_update_farmer_arc = farmer_arc.clone();
        let pool_state_run = global_run.clone();
        let pool_state_handle = tokio::spawn(async move {
            let mut last_update = Instant::now();
            let mut first = true;
            loop {
                if !*pool_state_run.lock().await {
                    break;
                }
                if first || Instant::now().duration_since(last_update).as_secs() >= 60 {
                    first = false;
                    debug!("Updating Pool State");
                    update_pool_state(pool_update_farmer_arc.clone()).await;
                    last_update = Instant::now();
                }
                tokio::time::sleep(Duration::from_secs(1)).await
            }
        });
        loop {
            debug!("Farmer Starting");
            let farmer = farmer_arc.clone();
            {
                let config = farmer.config.lock().await;
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
                if let (Some(public_crt), Some(public_key), Some(ca_public_crt)) = (
                    &config.farmer.ssl.certs.public_crt,
                    &config.farmer.ssl.certs.public_key,
                    &config.farmer.ssl.ca.public_crt,
                ) {
                    let ssl_crt_path = format!("{}/{}", &config.farmer.ssl.root_path, public_crt);
                    let ssl_key_path = format!("{}/{}", &config.farmer.ssl.root_path, public_key);
                    let ssl_ca_crt_path =
                        format!("{}/{}", &config.farmer.ssl.root_path, ca_public_crt);
                    let network_id = config.selected_network.as_str();
                    *farmer.full_node_client.lock().await = match FarmerClient::new_ssl(
                        host,
                        port,
                        &ssl_crt_path,
                        &ssl_key_path,
                        &ssl_ca_crt_path,
                        network_id,
                    )
                    .await
                    {
                        Ok(c) => Some(c),
                        Err(e) => {
                            debug!(
                                "Failed to Start Farmer Client, Waiting and trying again: {:?}",
                                e
                            );
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            if !*global_run.lock().await {
                                break;
                            }
                            continue;
                        }
                    };
                } else {
                    let network_id = config.selected_network.as_str();
                    *farmer.full_node_client.lock().await =
                        match FarmerClient::new(host, port, network_id).await {
                            Ok(c) => Some(c),
                            Err(e) => {
                                debug!(
                                    "Failed to Start Farmer Client, Waiting and trying again: {:?}",
                                    e
                                );
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                if !*global_run.lock().await {
                                    break;
                                }
                                continue;
                            }
                        };
                }
            }
            if let Some(fnc) = farmer.full_node_client.lock().await.as_ref() {
                let client = fnc.client.lock().await;
                let signage_handle_id = Uuid::new_v4();
                let signage_handle = Arc::new(NewSignagePointHandle {
                    id: signage_handle_id,
                    peers: farmer.peers.clone(),
                    pool_state: farmer.pool_state.clone(),
                    signage_points: farmer.signage_points.clone(),
                    cache_time: Arc::new(Default::default()),
                });
                client
                    .subscribe(
                        signage_handle_id,
                        ChiaMessageHandler::new(
                            ChiaMessageFilter {
                                msg_type: Some(ProtocolMessageTypes::NewSignagePoint),
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
                });
                client
                    .subscribe(
                        request_signed_values_id,
                        ChiaMessageHandler::new(
                            ChiaMessageFilter {
                                msg_type: Some(ProtocolMessageTypes::RequestSignedValues),
                            },
                            request_signed_values_handle,
                        ),
                    )
                    .await;
            }
            debug!("Farmer Initialized");
            loop {
                if let Some(client) = farmer.full_node_client.lock().await.as_ref() {
                    if client.is_closed() {
                        break;
                    }
                } else if !*global_run.lock().await {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            if !*global_run.lock().await {
                break;
            }
        }
        let _ = join!(server_handle, pool_state_handle);
    }

    pub async fn get_pool_info(pool_config: &PoolWalletConfig) -> Option<GetPoolInfoResponse> {
        match reqwest::get(format!("{}/pool_info", pool_config.pool_url)).await {
            Ok(resp) => match resp.status() {
                reqwest::StatusCode::OK => match resp.text().await {
                    Ok(body) => match serde_json::from_str(body.as_str()) {
                        Ok(c) => {
                            return Some(c);
                        }
                        Err(e) => {
                            warn!("Failed to load Pool Info, Invalid Json: {:?}, {}", e, body);
                        }
                    },
                    Err(e) => {
                        warn!("Failed to load Pool Info, Invalid Body: {:?}", e);
                    }
                },
                _ => {
                    warn!(
                        "Failed to load Pool Info, Bad Status Code: {:?}, {}",
                        resp.status(),
                        resp.text().await.unwrap_or_default()
                    );
                }
            },
            Err(e) => {
                warn!("Failed to load Pool Info: {:?}", e);
            }
        }
        None
    }

    pub async fn get_farmer(
        &self,
        pool_config: &PoolWalletConfig,
        authentication_token_timeout: u8,
        authentication_sk: &SecretKey,
    ) -> Result<GetFarmerResponse, PoolError> {
        let authentication_token = get_current_authentication_token(authentication_token_timeout);
        let signature = sign(
            authentication_sk,
            hash_256(
                AuthenticationPayload {
                    method_name: "get_farmer".to_string(),
                    launcher_id: pool_config.launcher_id.clone(),
                    target_puzzle_hash: pool_config.target_puzzle_hash.clone(),
                    authentication_token,
                }
                .to_bytes(),
            )
            .as_slice(),
        );
        self.pool_client
            .get_farmer(
                &pool_config.pool_url,
                GetFarmerRequest {
                    launcher_id: pool_config.launcher_id.clone(),
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
        if owner_sk.sk_to_pk().to_bytes() != pool_config.owner_public_key.to_sized_bytes() {
            return Err(PoolError {
                error_code: PoolErrorCode::ServerException as u8,
                error_message: "Owner Keys Mismatch".to_string(),
            });
        }
        if let Some(s) = self
            .auth_keys
            .lock()
            .await
            .get(&pool_config.p2_singleton_puzzle_hash)
        {
            Ok(s.sk_to_pk().to_bytes().into())
        } else {
            Err(PoolError {
                error_code: PoolErrorCode::ServerException as u8,
                error_message: "Authentication Public Key Not Found".to_string(),
            })
        }
    }

    pub async fn post_farmer(
        &self,
        pool_config: &PoolWalletConfig,
        authentication_token_timeout: u8,
        owner_sk: &SecretKey,
    ) -> Result<PostFarmerResponse, PoolError> {
        let payload = PostFarmerPayload {
            launcher_id: pool_config.launcher_id.clone(),
            authentication_token: get_current_authentication_token(authentication_token_timeout),
            authentication_public_key: self.do_auth(pool_config, owner_sk).await?,
            payout_instructions: pool_config.payout_instructions.clone(),
            suggested_difficulty: None,
        };
        let signature = sign(owner_sk, &hash_256(payload.to_bytes()));
        self.pool_client
            .post_farmer(
                &pool_config.pool_url,
                PostFarmerRequest {
                    payload,
                    signature: signature.to_bytes().into(),
                },
            )
            .await
    }

    pub async fn put_farmer(
        &self,
        pool_config: &PoolWalletConfig,
        authentication_token_timeout: u8,
        owner_sk: &SecretKey,
    ) -> Result<PutFarmerResponse, PoolError> {
        let authentication_public_key = self.do_auth(pool_config, owner_sk).await?;
        let payload = PutFarmerPayload {
            launcher_id: pool_config.launcher_id.clone(),
            authentication_token: get_current_authentication_token(authentication_token_timeout),
            authentication_public_key: Some(authentication_public_key),
            payout_instructions: Some(pool_config.payout_instructions.clone()),
            suggested_difficulty: None,
        };
        let signature = sign(owner_sk, &hash_256(payload.to_bytes()));
        let request = PutFarmerRequest {
            payload,
            signature: signature.to_bytes().into(),
        };
        self.pool_client
            .put_farmer(&pool_config.pool_url, request)
            .await
    }

    pub async fn update_pool_farmer_info(
        &self,
        pool_state: &mut FarmerPoolState,
        pool_config: &PoolWalletConfig,
        authentication_token_timeout: u8,
        authentication_sk: &SecretKey,
    ) -> Result<GetFarmerResponse, PoolError> {
        let response = self
            .get_farmer(pool_config, authentication_token_timeout, authentication_sk)
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

pub async fn update_pool_state(farmer: Arc<Farmer>) {
    let config = farmer.config.lock().await.clone();
    for pool_config in &config.pool_list {
        let farmer_key = farmer
            .auth_keys
            .lock()
            .await
            .get(&pool_config.p2_singleton_puzzle_hash)
            .cloned();
        if let Some(auth_secret_key) = farmer_key {
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
                        pool_config.p2_singleton_puzzle_hash.clone(),
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
                let pool_info = Farmer::get_pool_info(pool_config).await;
                if let Some(pool_info) = pool_info {
                    pool_state.authentication_token_timeout =
                        Some(pool_info.authentication_token_timeout);
                    // Only update the first time from GET /pool_info, gets updated from GET /farmer later
                    if pool_state.current_difficulty.is_none() {
                        pool_state.current_difficulty = Some(pool_info.minimum_difficulty);
                    }
                } else {
                    pool_state.next_pool_info_update = Instant::now()
                        + Duration::from_secs(UPDATE_POOL_INFO_FAILURE_RETRY_INTERVAL);
                    debug!("Update Pool Info Error");
                }
            } else {
                debug!("Not Ready for Update");
            }
            if Instant::now() >= pool_state.next_farmer_update {
                pool_state.next_farmer_update =
                    Instant::now() + Duration::from_secs(UPDATE_POOL_FARMER_INFO_INTERVAL);
                if let Some(authentication_token_timeout) = pool_state.authentication_token_timeout
                {
                    let farmer_info = match farmer
                        .update_pool_farmer_info(
                            &mut pool_state,
                            pool_config,
                            authentication_token_timeout,
                            &auth_secret_key,
                        )
                        .await
                    {
                        Ok(resp) => Some(resp),
                        Err(e) => {
                            if e.error_code == PoolErrorCode::FarmerNotKnown as u8 {
                                match &farmer
                                    .owner_secret_keys
                                    .lock()
                                    .await
                                    .get(&pool_config.owner_public_key.to_sized_bytes().into())
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
                                            .post_farmer(
                                                pool_config,
                                                authentication_token_timeout,
                                                sk,
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
                                                &auth_secret_key,
                                            )
                                            .await
                                        {
                                            Ok(resp) => Some(resp),
                                            Err(e) => {
                                                error!("Failed to update farmer info after POST /farmer. {:?}", e);
                                                None
                                            }
                                        }
                                    }
                                }
                            } else if e.error_code == PoolErrorCode::InvalidSignature as u8 {
                                match &farmer
                                    .owner_secret_keys
                                    .lock()
                                    .await
                                    .get(&pool_config.owner_public_key.to_sized_bytes().into())
                                {
                                    None => {
                                        error!(
                                            "Could not find Owner SK for {}",
                                            &pool_config.owner_public_key
                                        );
                                        continue;
                                    }
                                    Some(sk) => {
                                        let _ = farmer
                                            .put_farmer(
                                                pool_config,
                                                authentication_token_timeout,
                                                sk,
                                            )
                                            .await; //Todo maybe add logging here
                                    }
                                }
                                farmer
                                    .update_pool_farmer_info(
                                        &mut pool_state,
                                        pool_config,
                                        authentication_token_timeout,
                                        &auth_secret_key,
                                    )
                                    .await
                                    .ok()
                            } else {
                                None
                            }
                        }
                    };
                    let payout_instructions_update_required = if let Some(info) = farmer_info {
                        pool_config.payout_instructions.to_ascii_lowercase()
                            != info.payout_instructions.to_ascii_lowercase()
                    } else {
                        false
                    };
                    if payout_instructions_update_required {
                        match &farmer
                            .owner_secret_keys
                            .lock()
                            .await
                            .get(&pool_config.owner_public_key.to_sized_bytes().into())
                        {
                            None => {
                                error!(
                                    "Could not find Owner SK for {}",
                                    &pool_config.owner_public_key
                                );
                                continue;
                            }
                            Some(sk) => {
                                let _ = farmer
                                    .put_farmer(pool_config, authentication_token_timeout, sk)
                                    .await; //Todo maybe add logging here
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
                    .insert(pool_config.p2_singleton_puzzle_hash.clone(), pool_state);
            }
        } else {
            warn!(
                "Could not find authentication sk for: {:?}",
                &pool_config.p2_singleton_puzzle_hash
            );
        }
    }
}

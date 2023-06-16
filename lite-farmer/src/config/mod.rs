pub mod tls;

use dg_xch_core::blockchain::sized_bytes::{Bytes32, Bytes48};
use dg_xch_core::consensus::constants::CONSENSUS_CONSTANTS_MAP;
use dg_xch_keys::decode_puzzle_hash;
use paperclip::actix::Apiv2Schema;
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

#[derive(
    Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Apiv2Schema,
)]
pub struct Peer {
    pub host: String,
    pub port: u16,
}

#[derive(
    Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Apiv2Schema,
)]
pub struct SslCertInfo {
    #[serde(default)]
    pub public_crt: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    pub private_crt: String,
    pub private_key: String,
}

#[derive(
    Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Apiv2Schema,
)]
pub struct SslInfo {
    pub root_path: String,
    pub certs: SslCertInfo,
    pub ca: SslCertInfo,
}

#[derive(
    Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Apiv2Schema,
)]
pub struct FullNodeConfig {
    pub host: String,
    pub port: u16,
}

#[derive(
    Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Apiv2Schema,
)]
pub struct FarmerConfig {
    pub host: String,
    pub port: u16,
    pub local_full_node_peer: Option<Peer>,
    pub remote_full_node_peer: Peer,
    #[serde(default)]
    pub ssl: SslInfo,
    pub farming_info: Vec<FarmingInfo>,
    pub xch_target_address: String,
}

#[derive(
    Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Apiv2Schema,
)]
pub struct HarvesterConfig {
    pub host: String,
    pub port: u16,
    pub farmer_peer: Peer,
    pub ssl: SslInfo,
    pub plot_directories: Vec<String>,
}

#[derive(
    Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Apiv2Schema,
)]
pub struct FarmingInfo {
    pub farmer_secret_key: String,
    pub launcher_id: Option<String>,
    pub pool_secret_key: Option<String>,
    pub owner_secret_key: Option<String>,
}

#[derive(
    Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Apiv2Schema,
)]
pub struct PoolWalletConfig {
    pub launcher_id: Bytes32,
    pub pool_url: String,
    pub target_puzzle_hash: Bytes32,
    pub p2_singleton_puzzle_hash: Bytes32,
    pub owner_public_key: Bytes48,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Apiv2Schema)]
pub struct Config {
    pub version: u8,
    pub worker_name: String,
    pub selected_network: String,
    pub farmer: FarmerConfig,
    pub harvester: HarvesterConfig,
    pub pool_info: Vec<PoolWalletConfig>,
    pub license: bool,
    #[serde(skip_serializing, skip_deserializing)]
    pub path: String,
}
impl Config {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn save_as_yaml<P: AsRef<Path>>(&self, path: Option<P>) -> Result<(), Error> {
        if let Some(p) = path {
            fs::write(
                p.as_ref(),
                serde_yaml::to_string(&self)
                    .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))?,
            )
        } else {
            fs::write(
                Path::new(&self.path),
                serde_yaml::to_string(&self)
                    .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))?,
            )
        }
    }
    pub fn is_ready(&self) -> bool {
        self.license
            && CONSENSUS_CONSTANTS_MAP
                .get(&self.selected_network)
                .is_some()
            && !self.worker_name.is_empty()
            && !self.farmer.xch_target_address.is_empty()
            && decode_puzzle_hash(&self.farmer.xch_target_address).is_ok()
            && !self.farmer.farming_info.is_empty()
            && !self.harvester.plot_directories.is_empty()
    }
    pub fn merge_with(&mut self, other: &Config) {
        if self.worker_name.is_empty() && !other.worker_name.is_empty() {
            self.worker_name = other.worker_name.clone();
        }
        if self.selected_network.is_empty() && !other.selected_network.is_empty() {
            self.selected_network = other.selected_network.clone();
        }
        if self.farmer.host.is_empty() && !other.farmer.host.is_empty() {
            self.farmer.host = other.farmer.host.clone();
        }
        if self.farmer.host.is_empty() && !other.farmer.host.is_empty() {
            self.farmer.host = other.farmer.host.clone();
            self.farmer.port = other.farmer.port;
        }
        if self.farmer.remote_full_node_peer.host.is_empty()
            && !other.farmer.remote_full_node_peer.host.is_empty()
        {
            self.farmer.remote_full_node_peer.host =
                other.farmer.remote_full_node_peer.host.clone();
            self.farmer.remote_full_node_peer.port = other.farmer.remote_full_node_peer.port;
        }
        if let Some(other_local) = &other.farmer.local_full_node_peer {
            if let Some(local) = &mut self.farmer.local_full_node_peer {
                if local.host.is_empty() && !other_local.host.is_empty() {
                    local.host = other_local.host.clone();
                    local.port = other_local.port;
                }
            } else {
                self.farmer.local_full_node_peer = other.farmer.local_full_node_peer.clone();
            }
        }
        if self.farmer.ssl.root_path.is_empty() && !other.farmer.ssl.root_path.is_empty() {
            self.farmer.ssl.root_path = other.farmer.ssl.root_path.clone();
        }
        for farming_info in other.farmer.farming_info.iter() {
            if self.farmer.farming_info.iter().any(|i| {
                i.launcher_id.is_some() && i.launcher_id == farming_info.launcher_id
                    || i.pool_secret_key.is_some()
                        && i.pool_secret_key == farming_info.pool_secret_key
            }) {
                continue;
            } else {
                self.farmer.farming_info.push(farming_info.clone());
            }
        }

        if self.harvester.host.is_empty() && !other.harvester.host.is_empty() {
            self.harvester.host = other.harvester.host.clone();
            self.harvester.port = other.harvester.port;
        }
        if self.harvester.farmer_peer.host.is_empty()
            && !other.harvester.farmer_peer.host.is_empty()
        {
            self.harvester.farmer_peer.host = other.harvester.farmer_peer.host.clone();
            self.harvester.farmer_peer.port = other.harvester.farmer_peer.port;
        }
        if self.harvester.ssl.root_path.is_empty() && !other.harvester.ssl.root_path.is_empty() {
            self.harvester.ssl.root_path = other.harvester.ssl.root_path.clone();
        }
        for pool_info in other.pool_info.iter() {
            if self
                .pool_info
                .iter()
                .any(|i| i.launcher_id == pool_info.launcher_id)
            {
                continue;
            } else {
                self.pool_info.push(pool_info.clone());
            }
        }
    }
}
static CONFIG_VERSION: u8 = 2;

impl Default for Config {
    fn default() -> Self {
        Config {
            version: CONFIG_VERSION,
            worker_name: "lite-farmer".to_string(),
            selected_network: "mainnet".to_string(),
            farmer: FarmerConfig {
                host: "localhost".to_string(),
                port: 8447,
                local_full_node_peer: None,
                remote_full_node_peer: Peer {
                    host: "localhost".to_string(),
                    port: 8444,
                },
                ssl: SslInfo {
                    root_path: "./ssl/".to_string(),
                    certs: SslCertInfo {
                        public_crt: Some("farmer/public_farmer.crt".to_string()),
                        public_key: Some("farmer/public_farmer.key".to_string()),
                        private_crt: "farmer/private_farmer.crt".to_string(),
                        private_key: "farmer/private_farmer.key".to_string(),
                    },
                    ca: SslCertInfo {
                        public_crt: Some("ca/chia_ca.crt".to_string()),
                        public_key: Some("ca/chia_ca.key".to_string()),
                        private_crt: "ca/private_ca.crt".to_string(),
                        private_key: "ca/private_ca.key".to_string(),
                    },
                },
                farming_info: vec![],
                xch_target_address: String::new(),
            },
            harvester: HarvesterConfig {
                host: "localhost".to_string(),
                port: 8448,
                farmer_peer: Peer {
                    host: "localhost".to_string(),
                    port: 8447,
                },
                ssl: SslInfo {
                    root_path: "./ssl/".to_string(),
                    certs: SslCertInfo {
                        public_crt: None,
                        public_key: None,
                        private_crt: "harvester/private_harvester.crt".to_string(),
                        private_key: "harvester/private_harvester.key".to_string(),
                    },
                    ca: SslCertInfo {
                        public_crt: Some("ca/chia_ca.crt".to_string()),
                        public_key: Some("ca/chia_ca.key".to_string()),
                        private_crt: "ca/private_ca.crt".to_string(),
                        private_key: "ca/private_ca.key".to_string(),
                    },
                },
                plot_directories: vec![],
            },
            pool_info: vec![],
            license: false,
            path: String::from("./farmer_config.yaml"),
        }
    }
}
impl TryFrom<&Path> for Config {
    type Error = Error;
    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        serde_yaml::from_str::<Config>(&fs::read_to_string(value)?)
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))
    }
}
impl TryFrom<&PathBuf> for Config {
    type Error = Error;
    fn try_from(value: &PathBuf) -> Result<Self, Self::Error> {
        Self::try_from(value.as_path())
    }
}

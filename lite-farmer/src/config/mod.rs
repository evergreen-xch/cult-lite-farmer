pub mod tls;

use dg_xch_utils::types::blockchain::sized_bytes::{Bytes32, Bytes48};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Peer {
    pub host: String,
    pub port: u16,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SslCertInfo {
    #[serde(default)]
    pub public_crt: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    pub private_crt: String,
    pub private_key: String,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SslInfo {
    pub root_path: String,
    pub certs: SslCertInfo,
    pub ca: SslCertInfo,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FullNodeConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FarmerConfig {
    pub host: String,
    pub port: u16,
    pub local_full_node_peer: Option<Peer>,
    pub remote_full_node_peer: Peer,
    pub ssl: SslInfo,
    pub farming_info: Vec<FarmingInfo>,
    pub xch_target_address: String,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HarvesterConfig {
    pub host: String,
    pub port: u16,
    pub farmer_peer: Peer,
    pub ssl: SslInfo,
    pub plot_directories: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FarmingInfo {
    pub farmer_secret_key: String,
    pub launcher_id: Option<String>,
    pub pool_secret_key: Option<String>,
    pub owner_secret_key: Option<String>,
    pub auth_secret_key: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PoolWalletConfig {
    pub launcher_id: Bytes32,
    pub pool_url: String,
    pub payout_instructions: String,
    pub target_puzzle_hash: Bytes32,
    pub p2_singleton_puzzle_hash: Bytes32,
    pub owner_public_key: Bytes48,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub worker_name: String,
    pub selected_network: String,
    pub farmer: FarmerConfig,
    pub harvester: HarvesterConfig,
    pub pool_list: Vec<PoolWalletConfig>,
    pub license: bool,
    #[serde(skip_serializing, skip_deserializing)]
    pub path: PathBuf,
}
impl Config {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn save_as_yaml<P: AsRef<Path>>(&self, path: Option<P>) -> Result<(), std::io::Error> {
        if let Some(p) = path {
            fs::write(
                p.as_ref(),
                serde_yaml::to_string(&self)
                    .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("{:?}", e)))?,
            )
        } else {
            fs::write(
                self.path.as_path(),
                serde_yaml::to_string(&self)
                    .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("{:?}", e)))?,
            )
        }
    }
}
impl Default for Config {
    fn default() -> Self {
        Config {
            worker_name: "lite-farmer".to_string(),
            selected_network: "mainnet".to_string(),
            farmer: FarmerConfig {
                host: "127.0.0.1".to_string(),
                port: 8447,
                local_full_node_peer: Some(Peer {
                    host: "127.0.0.1".to_string(),
                    port: 8444,
                }),
                remote_full_node_peer: Peer {
                    host: "127.0.0.1".to_string(),
                    port: 8444,
                },
                ssl: SslInfo {
                    root_path: "./ssl/".to_string(),
                    certs: SslCertInfo {
                        public_crt: None,
                        public_key: None,
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
                farming_info: vec![FarmingInfo {
                    farmer_secret_key: "YOUR SECRET KEY HERE".to_string(),
                    launcher_id: Some(
                        "If Using a PlotNFT put YOUR LAUNCHER ID HERE, otherwise leave blank"
                            .to_string(),
                    ),
                    pool_secret_key: Some(
                        "If Using a OG Plot, otherwise leave blank, YOUR POOL SECRET KEY"
                            .to_string(),
                    ),
                    owner_secret_key: Some(
                        "If Using a PlotNFT put YOUR OWNER SECRET KEY, otherwise leave blank"
                            .to_string(),
                    ),
                    auth_secret_key: Some(
                        "If Using a PlotNFT put YOUR AUTH SECRET KEY, otherwise leave blank"
                            .to_string(),
                    ),
                }],
                xch_target_address: "YOUR PAYOUT ADDRESS HERE".to_string(),
            },
            harvester: HarvesterConfig {
                host: "127.0.0.1".to_string(),
                port: 8448,
                farmer_peer: Peer {
                    host: "127.0.0.1".to_string(),
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
            pool_list: vec![],
            license: false,
            path: PathBuf::from("./farmer_config.yaml"),
        }
    }
}
impl TryFrom<&Path> for Config {
    type Error = std::io::Error;
    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        serde_yaml::from_str::<Config>(&fs::read_to_string(value)?)
            .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("{:?}", e)))
    }
}
impl TryFrom<&PathBuf> for Config {
    type Error = std::io::Error;
    fn try_from(value: &PathBuf) -> Result<Self, Self::Error> {
        Self::try_from(value.as_path())
    }
}

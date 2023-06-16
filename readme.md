lite-farmer
=====

A lite farmer and harvester for the Chia Blockchain.

Building
--------

Install Rust:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Build from source:

```
git clone https://github.com/evergreen-xch/chia-lite-farmer.git
cd chia-lite-farmer
cargo build --release
```

Running
--------

First generate a config, this will search for PlotNFTs that belong to your keys and create a config for the selected network

```
cargo run --release --bin lite-farmer -- run --release --bin lite-farmer -- -c "/path/to/config/farmer_config.yaml" init -m "MNEMONIC" -f FULLNODE_HOST -p FULLNODE_RPC_PORT -n SELECTED_NETWORK
```

Then Start the Farmer and Harvester:

```
cargo run --release --bin lite-farmer -- -c "/path/to/config/farmer_config.yaml" run farmer harvester
```

Docker
--------

Run the script, this will create a lite-farmer.tar file, current supported platforms are linux/amd64 and linux/arm64, specified in the script file by the platform flag

```
./build_docker.sh
```

To Import the tar into docker:

```
docker load -i lite_farmer.tar 
```

Tag the image and run it:
```
docker tag IMAGE_ID lite-farmer
docker run -d 
    --network=host 
    --mount type=bind,src=/PATH/TO/farmer_config.yaml,dst=/farmer_config.yaml 
    --mount type=bind,src=/PATH/TO/ssl/,dst=/ssl 
    --mount type=bind,src=/PATH/TO/mnt/,dst=/mnt/ 
    -e RUST_LOG=INFO 
    lite-farmer 
    bash -c "./lite-farmer -c /farmer_config.yaml run farmer harvester"
```
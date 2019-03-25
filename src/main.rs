#![feature(await_macro, async_await, futures_api, generators)]
#[macro_use]
extern crate lazy_static;

use std::path::PathBuf;

use futures::channel::mpsc;
use futures::executor::{self, ThreadPool};
use futures::prelude::*;
use futures::task::SpawnExt;
use log::{debug, error, info};

use crate::rpc::message::BootstrapMessage;
use crate::rpc::message::EmptyMessage;
use crate::rpc::message::PeerURL;
use crate::tezos::storage::db::Db;
use std::path::Path;

mod tezos;
mod rpc;
mod configuration;

const LOG_FILE: &str = "log4rs.yml";
pub const MPSC_BUFFER_SIZE: usize = 50;

fn main() {
    use std::process::exit;
    use crate::tezos::p2p::client::P2pClient;

    match log4rs::init_file(LOG_FILE, Default::default()) {
        Ok(_) => debug!("Logger configured from file: {}", LOG_FILE),
        Err(m) => {
            eprintln!("Logger configuration file {} error {}", LOG_FILE, m);
            exit(1)
        }
    }

    let initial_peers: Vec<PeerURL> = configuration::ENV.initial_peers.clone()
        .into_iter()
        .map(|(ip, port)| {
            PeerURL {
                host: ip.clone(),
                port: port.clone(),
            }
        })
        .collect();

    let identity_json_file_path: PathBuf = configuration::ENV.identity_json_file_path.clone()
        .unwrap_or_else(|| {
            let tezos_default_identity: PathBuf = configuration::tezos_node::get_default_tezos_identity_json_file_path().unwrap();
            if tezos_default_identity.exists() {
                // if exists tezos default location, then use it
                tezos_default_identity
            } else {
                // or just use our config/identity.json
                let tezos_default_identity = Path::new("./config/identity.json").to_path_buf();
                tezos_default_identity
            }
        });

    info!("Starting Iron p2p");

    executor::block_on(async move {

        let mut thread_pool = ThreadPool::new().expect("Failed to create thread pool");
        let (mut rpc_tx, rpc_rx) = mpsc::channel(MPSC_BUFFER_SIZE);
        let (_, p2p_rx) = mpsc::channel(MPSC_BUFFER_SIZE);

        let p2p_client = P2pClient::new(
            hex::decode(configuration::tezos_node::genesis_chain_id()).unwrap(),
            configuration::tezos_node::load_identity(identity_json_file_path).unwrap(),
            configuration::tezos_node::versions(),
            Db::new()
        );

        let res = thread_pool.spawn(
            tezos::p2p::node::forward_rpc_messages_to_p2p(
                rpc_rx,
                thread_pool.clone(),
                p2p_client.clone()
            )
        );
        if let Err(e) = res {
            error!("Failed to start RPC message consuming task. Reason: {:?}", e);
            return;
        }
        let res = thread_pool.spawn(rpc::server::forward_p2p_messages_to_rpc(p2p_rx));
        if let Err(e) = res {
            error!("Failed to start P2P message consuming task. Reason: {:?}", e);
            return;
        }

        // init node bootstrap
        if initial_peers.is_empty() == false {
            await!(rpc_tx.send((rpc::message::RpcMessage::BootstrapWithPeers(BootstrapMessage { initial_peers }), None)))
                .expect("Failed to transmit bootstrap message to p2p layer")
        } else {
            await!(rpc_tx.send((rpc::message::RpcMessage::BootstrapWithLookup(EmptyMessage {}), None)))
                .expect("Failed to transmit bootstrap message to p2p layer")
        }

        // ------------------
        // Lines after the following block will be executed only after accept_connections() task will complete
        // ------------------
        let res = await!(rpc::server::accept_connections(rpc_tx.clone(), thread_pool));
        if let Err(e) = res {
            error!("Failed to start accepting RPC connections. Reason: {:?}", e);
            return;
        }

    });


    info!("Iron p2p stopped")
}

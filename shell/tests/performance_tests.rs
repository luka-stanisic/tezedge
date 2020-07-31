// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT
#![feature(test)]
extern crate test;

/// Performance tests for different scenarious
/// 1. test_insert_data + bench_test_insert_data* - verify and optimize db configuration
///
/// Run tests:
/// 1. RUSTFLAGS="-Z sanitizer=leak" cargo test --release test_performance_insert_data
/// 2. cargo bench --tests test_performance -- --nocapture
///
/// prefix 'test_performance' is used in drone tests

use slog::Logger;

use storage::tests_common::TmpStorage;

mod common;

#[test]
fn test_performance_insert_data() -> Result<(), failure::Error> {
    let tmp_storage = TmpStorage::create(common::prepare_empty_dir("__performance_test_insert_data"))?;
    assert!(scenario::insert_data_scenario(tmp_storage, logger()).is_ok());
    Ok(())
}

// run as: cargo bench --tests --nocapture
mod benches {
    use std::sync::atomic::Ordering;
    use test::Bencher;

    use failure::_core::sync::atomic::AtomicUsize;

    use storage::persistent::{DbOptions, default_kv_options, tunned_kv_options};

    use crate::*;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[bench]
    fn bench_test_performance_insert_data_with_default_db_options(b: &mut Bencher) {
        test_insert_data_with_db_options(b, default_kv_options())
    }

    #[bench]
    fn bench_test_performance_insert_data_with_tunned_db_options(b: &mut Bencher) {
        test_insert_data_with_db_options(b, tunned_kv_options())
    }

    fn test_insert_data_with_db_options(b: &mut Bencher, opts: DbOptions) {
        b.iter(|| {
            let storage_path = format!("bench_test_insert_data_{}", COUNTER.fetch_add(1, Ordering::SeqCst));
            let tmp_storage = TmpStorage::create_with_opts(common::prepare_empty_dir(&storage_path), &opts).expect("Storage not created");
            assert!(scenario::insert_data_scenario(tmp_storage, logger()).is_ok());
        });
    }
}

fn logger() -> Logger {
    common::create_logger(common::log_level())
}

mod scenario {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use slog::Logger;

    use storage::{BlockHeaderWithHash, BlockMetaStorage, BlockStorage, MempoolStorage, OperationsMetaStorage, OperationsStorage};
    use storage::mempool_storage::MempoolOperationType;
    use storage::tests_common::TmpStorage;
    use tezos_api::environment::TEZOS_ENV;
    use tezos_api::environment::TezosEnvironmentConfiguration;
    use tezos_api::ffi::{ApplyBlockRequest, FfiMessage, RustBytes};
    use tezos_messages::p2p::binary_message::MessageHash;
    use tezos_messages::p2p::encoding::operations_for_blocks;
    use tezos_messages::p2p::encoding::prelude::{OperationMessage, OperationsForBlock, OperationsForBlocksMessage};

    use crate::test_data;

    pub fn insert_data_scenario(tmp_storage: TmpStorage, log: Logger) -> Result<(), failure::Error> {

        // environement
        let tezos_env: &TezosEnvironmentConfiguration = TEZOS_ENV.get(&test_data::TEZOS_NETWORK).expect("no environment configuration");

        // prepare dbs
        let persistent_storage = tmp_storage.storage();
        let mut block_storage = BlockStorage::new(&persistent_storage);
        let mut block_meta_storage = BlockMetaStorage::new(&persistent_storage);
        let mut operations_storage = OperationsStorage::new(&persistent_storage);
        let mut operations_meta_storage = OperationsMetaStorage::new(&persistent_storage);
        let mut mempool_storage = MempoolStorage::new(&persistent_storage);

        // we have stored 1326 request, apply just 1324, and 1325,1326 will be used for mempool test
        let requests = test_data::read_apply_block_requests_until_1326();
        let to_level = 1324;

        insert_block_and_operations_to_storage(
            tezos_env,
            &log,
            &requests,
            to_level,
            &mut block_storage,
            &mut block_meta_storage,
            &mut operations_storage,
            &mut operations_meta_storage,
            &mut mempool_storage,
        )
    }

    fn insert_block_and_operations_to_storage(
        tezos_env: &TezosEnvironmentConfiguration,
        log: &Logger,
        requests: &Vec<String>,
        to_level: i32,
        block_storage: &mut BlockStorage,
        block_meta_storage: &mut BlockMetaStorage,
        operations_storage: &mut OperationsStorage,
        operations_meta_storage: &mut OperationsMetaStorage,
        mempool_storage: &mut MempoolStorage,
    ) -> Result<(), failure::Error> {
        let chain_id = tezos_env.main_chain_id().expect("invalid chain id");

        // let's insert stored requests to database
        for request in requests {

            // parse request
            let request: RustBytes = hex::decode(request)?;
            let request = ApplyBlockRequest::from_rust_bytes(request)?;
            let header = request.block_header.clone();

            // store header to db
            let block = BlockHeaderWithHash {
                hash: header.message_hash()?,
                header: Arc::new(header),
            };
            block_storage.put_block_header(&block)?;
            block_meta_storage.put_block_header(&block, &chain_id, log.clone())?;
            operations_meta_storage.put_block_header(&block, &chain_id)?;

            // store operations to db
            let operations = request.operations.clone();
            for (idx, ops) in operations.iter().enumerate() {
                let opb = OperationsForBlock::new(block.hash.clone(), idx as i8);
                let msg: OperationsForBlocksMessage = OperationsForBlocksMessage::new(opb, operations_for_blocks::Path::Op, ops.clone());
                operations_storage.put_operations(&msg)?;
                operations_meta_storage.put_operations(&msg)?;
                if !msg.operations().is_empty() {
                    let ttl = SystemTime::now() + Duration::from_secs(60);
                    mempool_storage.put(MempoolOperationType::Pending, OperationMessage::new(msg.operations()[0].clone()), ttl)?;
                }
            }
            assert!(operations_meta_storage.is_complete(&block.hash)?);

            if block.header.level() >= to_level {
                break;
            }
        }

        Ok(())
    }
}

mod test_data {
    use std::{env, io};
    use std::fs::File;
    use std::path::Path;

    use tezos_api::environment::TezosEnvironment;

    pub const TEZOS_NETWORK: TezosEnvironment = TezosEnvironment::Carthagenet;

    pub fn read_apply_block_requests_until_1326() -> Vec<String> {
        let path = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("tests")
            .join("resources")
            .join("apply_block_request_until_1326.zip");
        let file = File::open(path).expect("Couldn't open file: tests/resources/apply_block_request_until_1326.zip");
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let mut requests: Vec<String> = Vec::new();

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).unwrap();
            let mut writer: Vec<u8> = vec![];
            io::copy(&mut file, &mut writer).unwrap();
            requests.push(String::from_utf8(writer).expect("error"));
        }

        requests
    }
}

mod test_actor {
    use std::sync::{Arc, Mutex};
    use std::sync::mpsc::Sender as QueueSender;

    use riker::actors::*;
    use slog::{debug, warn};

    use shell::shell_channel::{CurrentMempoolState, ShellChannelMsg, ShellChannelRef, ShellChannelTopic};

    #[actor(ShellChannelMsg)]
    pub(crate) struct TestActor {
        result_sender: Arc<Mutex<QueueSender<CurrentMempoolState>>>,
        shell_channel: ShellChannelRef,
    }

    pub type TestActorRef = ActorRef<TestActorMsg>;

    impl Actor for TestActor {
        type Msg = TestActorMsg;

        fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
            self.shell_channel.tell(Subscribe {
                actor: Box::new(ctx.myself()),
                topic: ShellChannelTopic::ShellEvents.into(),
            }, ctx.myself().into());
        }

        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Option<BasicActorRef>) {
            self.receive(ctx, msg, sender);
        }
    }

    impl ActorFactoryArgs<(ShellChannelRef, Arc<Mutex<QueueSender<CurrentMempoolState>>>)> for TestActor {
        fn create_args((shell_channel, result_sender): (ShellChannelRef, Arc<Mutex<QueueSender<CurrentMempoolState>>>)) -> Self {
            Self {
                shell_channel,
                result_sender,
            }
        }
    }

    impl Receive<ShellChannelMsg> for TestActor {
        type Msg = TestActorMsg;

        fn receive(&mut self, ctx: &Context<Self::Msg>, msg: ShellChannelMsg, _sender: Sender) {
            match self.process_shell_channel_message(ctx, msg) {
                Ok(_) => (),
                Err(e) => warn!(ctx.system.log(), "Failed to process shell channel message"; "reason" => format!("{:?}", e)),
            }
        }
    }

    impl TestActor {
        pub fn name() -> &'static str { "test-actor" }

        pub fn actor(sys: &ActorSystem, shell_channel: ShellChannelRef, result_sender: QueueSender<CurrentMempoolState>) -> Result<TestActorRef, CreateError> {
            Ok(
                sys.actor_of_props::<TestActor>(
                    Self::name(),
                    Props::new_args((shell_channel, Arc::new(Mutex::new(result_sender)))),
                )?
            )
        }

        fn process_shell_channel_message(&mut self, ctx: &Context<TestActorMsg>, msg: ShellChannelMsg) -> Result<(), failure::Error> {
            match msg {
                ShellChannelMsg::MempoolStateChanged(new_mempool_state) => {
                    debug!(ctx.system.log(), "TestActor received event"; "mempool" => format!("{:?}", new_mempool_state));
                    self.result_sender.lock().unwrap().send(new_mempool_state)?;
                }
                _ => ()
            }

            Ok(())
        }
    }
}
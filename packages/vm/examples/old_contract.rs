use std::collections::HashSet;
use tempfile::TempDir;

use clap::{App, Arg};
use cosmwasm_std::{coins, from_slice, to_vec, ContractResult, QueryResponse};
use cosmwasm_vm::testing::{mock_backend, mock_env, mock_info, MockApi};
use cosmwasm_vm::{
    call_execute_raw, call_instantiate_raw, call_query_raw, Cache, CacheOptions, InstanceOptions,
    Size,
};
use std::fs::File;
use std::io::prelude::*;

// Instance
const DEFAULT_MEMORY_LIMIT: Size = Size::mebi(64);
const DEFAULT_GAS_LIMIT: u64 = 400_000 * 150_000;
const DEFAULT_INSTANCE_OPTIONS: InstanceOptions = InstanceOptions {
    gas_limit: DEFAULT_GAS_LIMIT,
    print_debug: false,
};
// Cache
const MEMORY_CACHE_SIZE: Size = Size::mebi(200);

pub fn run_contract(src: &str) {
    let mut f = File::open(src).unwrap();
    let mut contract = vec![];
    f.read_to_end(&mut contract).unwrap();

    let options = CacheOptions {
        base_dir: TempDir::new().unwrap().into_path(),
        available_capabilities: HashSet::default(),
        memory_cache_size: MEMORY_CACHE_SIZE,
        instance_memory_limit: DEFAULT_MEMORY_LIMIT,
    };

    let cache = unsafe { Cache::new(options).unwrap() };

    let checksum = cache.save_wasm(&contract).unwrap();
    let mut backend = mock_backend(&[]);
    backend.api = MockApi::new(24); // same as old version
    let mut instance = cache
        .get_instance(&checksum, backend, DEFAULT_INSTANCE_OPTIONS)
        .unwrap();

    let msg = br#"{"name": "name", "version": "version", "symbol": "symbol","minter":"creator"}"#;
    let env = to_vec(&mock_env()).unwrap();
    let info = to_vec(&mock_info("creator", &coins(1000, "earth"))).unwrap();
    let contract_result = call_instantiate_raw::<_, _, _>(&mut instance, &env, &info, msg).unwrap();
    println!(
        "Done instantiating contract: {}",
        String::from_utf8(contract_result).unwrap()
    );

    let env = to_vec(&mock_env()).unwrap();
    let info = to_vec(&mock_info("creator", &coins(15, "earth"))).unwrap();
    let msg = br#"{"mint":{"token_id": "token_id", "owner": "owner", "name": "name", "description": "description", "image": "image"}}"#;
    let contract_result = call_execute_raw::<_, _, _>(&mut instance, &env, &info, msg).unwrap();
    println!(
        "Done excuting contract: {}",
        String::from_utf8(contract_result).unwrap()
    );

    let env = to_vec(&mock_env()).unwrap();
    let msg = br#"{"all_tokens":{}}"#;
    let data = call_query_raw::<_, _, _>(&mut instance, &env, msg).unwrap();
    let contract_result: ContractResult<QueryResponse> = from_slice(&data).unwrap();
    println!(
        "Done querying contract: {}",
        String::from_utf8(contract_result.unwrap().to_vec()).unwrap()
    );
}

pub fn main() {
    //
    let matches = App::new("Contract checking")
        .version("0.1.0")
        .long_about("Run a wasm contract (cargo run --package cosmwasm-vm --features cranelift,iterator --example old_contract -- packages/vm/testdata/oraichain_nft_0_13_2.wasm).")
        .author("Thanh Tu <tu@orai.io>")
        .arg(
            Arg::with_name("WASM")
                .help("Wasm file to read and compile")
                .default_value("packages/vm/testdata/oraichain_nft_0_13_2.wasm")
                .required(true)
                .index(1),
        )
        .get_matches();

    // File
    let path = matches.value_of("WASM").expect("Error parsing file name");

    run_contract(path);
}

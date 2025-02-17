use std::collections::HashSet;
use tempfile::TempDir;

use clap::{Arg, Command};
use cosmwasm_std::{coins, Empty};
use cosmwasm_vm::testing::{mock_backend, mock_env, mock_info};
use cosmwasm_vm::{
    call_execute, call_instantiate, call_migrate, call_query, Cache, CacheOptions, InstanceOptions,
    Size,
};
use std::fs::File;
use std::io::prelude::*;

// Instance
const DEFAULT_MEMORY_LIMIT: Size = Size::mebi(64);
const DEFAULT_GAS_LIMIT: u64 = 400_000 * 150_000;
const DEFAULT_INSTANCE_OPTIONS: InstanceOptions = InstanceOptions {
    gas_limit: DEFAULT_GAS_LIMIT,
};
// Cache
const MEMORY_CACHE_SIZE: Size = Size::mebi(200);

pub fn run_contract(src: &str) {
    let mut f = File::open(src).unwrap();
    let mut contract = vec![];
    f.read_to_end(&mut contract).unwrap();

    let options = CacheOptions::new(
        TempDir::new().unwrap().into_path(),
        HashSet::default(),
        MEMORY_CACHE_SIZE,
        DEFAULT_MEMORY_LIMIT,
    );

    let cache = unsafe { Cache::new(options).unwrap() };

    let checksum = cache.save_wasm(&contract).unwrap();
    let backend = mock_backend(&[]);
    let mut instance = cache
        .get_instance(&checksum, backend, DEFAULT_INSTANCE_OPTIONS)
        .unwrap();

    let env = mock_env();
    let info = mock_info("creator", &coins(15, "earth"));

    let msg = br#"{"name": "name", "version": "version", "symbol": "symbol","minter":"creator"}"#;
    let contract_result =
        call_instantiate::<_, _, _, Empty>(&mut instance, &env, &info, msg).unwrap();
    println!("Done instantiating contract: {:?}", contract_result);

    let msg = br#"{"mint":{"token_id": "token_id", "owner": "owner", "name": "name", "description": "description", "image": "image"}}"#;
    let contract_result = call_execute::<_, _, _, Empty>(&mut instance, &env, &info, msg).unwrap();
    println!("Done excuting contract: {:?}", contract_result);

    let msg = br#"{"send_nft":{"contract": "contract", "token_id": "token_id"}}"#;
    let contract_result =
        call_execute::<_, _, _, Empty>(&mut instance, &env, &mock_info("owner", &[]), msg).unwrap();
    println!("Done excuting contract with sub msg: {:?}", contract_result);

    let msg = br#"{"test_field":"nothing"}"#;
    let contract_result = call_migrate::<_, _, _, Empty>(&mut instance, &env, msg).unwrap();
    println!("Done migrating contract with msg: {:?}", contract_result);

    let msg = br#"{"all_tokens":{}}"#;
    let contract_result = call_query::<_, _, _>(&mut instance, &env, msg).unwrap();

    println!(
        "Done querying contract: {}",
        String::from_utf8(contract_result.into_result().unwrap().to_vec()).unwrap()
    );
}

pub fn main() {
    //
    let matches = Command::new("Contract checking")
        .version("0.1.0")
        .long_about("Run a wasm contract (cargo run --package cosmwasm-vm --features cranelift,iterator --example old_contract -- packages/vm/testdata/oraichain_nft_0_13_2.wasm).")
        .author("Thanh Tu <tu@orai.io>")
        .arg(
            Arg::new("WASM")
                .help("Wasm file to read and compile")                
                .required(true)
                .index(1),
        )
        .get_matches();

    // File
    let path: &String = matches.get_one("WASM").expect("Error parsing file name");

    run_contract(path);
}

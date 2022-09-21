use std::sync::Arc;
use tempfile::TempDir;

use cosmwasm_std::{coins, Empty};
use cosmwasm_vm::testing::{mock_backend, mock_env, mock_info};
use cosmwasm_vm::{
    call_execute, call_instantiate, features_from_csv, Cache, CacheOptions, InstanceOptions, Size,
};

// Instance
const DEFAULT_MEMORY_LIMIT: Size = Size::mebi(64);
const DEFAULT_GAS_LIMIT: u64 = 400_000 * 150_000;
const DEFAULT_INSTANCE_OPTIONS: InstanceOptions = InstanceOptions {
    gas_limit: DEFAULT_GAS_LIMIT,
    print_debug: false,
};
// Cache
const MEMORY_CACHE_SIZE: Size = Size::mebi(200);

static CONTRACT: &[u8] = include_bytes!("../testdata/oraichain_nft.wasm");

pub fn main() {
    let options = CacheOptions {
        base_dir: TempDir::new().unwrap().into_path(),
        supported_features: features_from_csv("staking"),
        memory_cache_size: MEMORY_CACHE_SIZE,
        instance_memory_limit: DEFAULT_MEMORY_LIMIT,
    };

    let cache = Arc::new(unsafe { Cache::new(options).unwrap() });

    let checksum = cache.save_wasm(CONTRACT).unwrap();

    let mut instance = cache
        .get_instance(&checksum, mock_backend(&[]), DEFAULT_INSTANCE_OPTIONS)
        .unwrap();

    let info = mock_info("creator", &coins(1000, "earth"));
    let msg = br#"{"name": "name", "version": "version", "symbol": "symbol","minter":"creator"}"#;
    let contract_result =
        call_instantiate::<_, _, _, Empty>(&mut instance, &mock_env(), &info, msg).unwrap();
    println!("Done instantiating contract");
    println!("result: {:?}", contract_result.into_result().unwrap());

    let info = mock_info("creator", &coins(15, "earth"));
    let msg = br#"{"mint":{"token_id": "token_id", "owner": "creator", "name": "name", "description": "description", "image": "image"}}"#;
    let contract_result =
        call_execute::<_, _, _, Empty>(&mut instance, &mock_env(), &info, msg).unwrap();
    println!("Done excuting contract");
    println!("{:?}", contract_result.into_result().unwrap());
}

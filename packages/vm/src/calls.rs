use ::serde::Deserialize;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt;
use wasmer::Val;

use cosmwasm_std::{
    Attribute, Binary, Coin, ContractInfo, ContractResult, CosmosMsg, Empty, Env, MessageInfo,
    QueryResponse,
};

use crate::backend::{BackendApi, Querier, Storage};
use crate::conversion::ref_to_u32;
use crate::errors::{VmError, VmResult};
use crate::instance::Instance;
use crate::serde::{from_slice, to_vec};

const MAX_LENGTH_INIT: usize = 100_000;
const MAX_LENGTH_EXECUTE: usize = 100_000;
const MAX_LENGTH_MIGRATE: usize = 100_000;
const MAX_LENGTH_SUDO: usize = 100_000;
const MAX_LENGTH_SUBCALL_RESPONSE: usize = 100_000;
const MAX_LENGTH_QUERY: usize = 100_000;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Response<T = Empty>
where
    T: Clone + fmt::Debug + PartialEq + JsonSchema,
{
    /// Optional list of "subcalls" to make. These will be executed in order
    /// (and this contract's subcall_response entry point invoked)
    /// *before* any of the "fire and forget" messages get executed.
    pub submessages: Vec<SubMsg<T>>,
    /// After any submessages are processed, these are all dispatched in the host blockchain.
    /// If they all succeed, then the transaction is committed. If any fail, then the transaction
    /// and any local contract state changes are reverted.
    pub messages: Vec<CosmosMsg<T>>,
    /// The attributes that will be emitted as part of a "wasm" event
    pub attributes: Vec<Attribute>,
    pub data: Option<Binary>,
}

impl<T> Default for Response<T>
where
    T: Clone + fmt::Debug + PartialEq + JsonSchema,
{
    fn default() -> Self {
        Response {
            submessages: vec![],
            messages: vec![],
            attributes: vec![],
            data: None,
        }
    }
}

impl<T> Response<T>
where
    T: Clone + fmt::Debug + PartialEq + JsonSchema,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_attribute<K: Into<String>, V: Into<String>>(&mut self, key: K, value: V) {
        self.attributes.push(Attribute {
            key: key.into(),
            value: value.into(),
        });
    }

    pub fn add_message<U: Into<CosmosMsg<T>>>(&mut self, msg: U) {
        self.messages.push(msg.into());
    }

    pub fn add_submessage<U: Into<CosmosMsg<T>>>(
        &mut self,
        id: u64,
        msg: U,
        gas_limit: Option<u64>,
        reply_on: ReplyOn,
    ) {
        let sub = SubMsg {
            id,
            msg: msg.into(),
            gas_limit,
            reply_on,
        };
        self.submessages.push(sub);
    }

    pub fn set_data<U: Into<Binary>>(&mut self, data: U) {
        self.data = Some(data.into());
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReplyOn {
    /// Always perform a callback after SubMsg is processed
    Always,
    /// Only callback if SubMsg returned an error, no callback on success case
    Error,
    /// Only callback if SubMsg was successful, no callback on error case
    Success,
}

impl Default for ReplyOn {
    fn default() -> Self {
        ReplyOn::Always
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct SubMsg<T = Empty>
where
    T: Clone + fmt::Debug + PartialEq + JsonSchema,
{
    pub id: u64,
    pub msg: CosmosMsg<T>,
    pub gas_limit: Option<u64>,
    pub reply_on: ReplyOn,
}
/// The Result object returned to subcall_response. We always get the same id back
/// and then must handle success and error cases ourselves
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Reply {
    pub id: u64,
    pub result: ContractResult<SubcallResponse>,
}

/// The information we get back from a successful sub-call, with full sdk events
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct SubcallResponse {
    pub events: Vec<Event>,
    pub data: Option<Binary>,
}

#[derive(Serialize)]
struct MessageInfoV0_13_2 {
    pub sender: String,
    pub sent_funds: Vec<Coin>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Event {
    #[serde(rename = "type")]
    pub kind: String,
    pub attributes: Vec<Attribute>,
}

impl Event {
    pub fn new(kind: &str, attributes: Vec<Attribute>) -> Self {
        Event {
            kind: kind.to_string(),
            attributes,
        }
    }
}

#[derive(Serialize)]
pub struct EnvV0_13_2 {
    pub block: BlockInfoV0_13_2,
    pub contract: ContractInfo,
}

#[derive(Serialize)]
pub struct BlockInfoV0_13_2 {
    pub height: u64,
    pub time: u64,
    pub time_nanos: u64,
    pub chain_id: String,
}

pub(crate) fn get_old_env(env: &[u8]) -> VmResult<Vec<u8>> {
    // let env_struct: Env = from_slice(env)?;
    // let old_env_struct = EnvV0_13_2 {
    //     block: BlockInfoV0_13_2 {
    //         // time in seconds
    //         time: env_struct.block.time.nanos() / 1_000_000_000,
    //         time_nanos: env_struct.block.time.nanos(),
    //         height: env_struct.block.height,
    //         chain_id: env_struct.block.chain_id,
    //     },
    //     contract: env_struct.contract,
    // };

    // to_vec(&old_env_struct)
    return Ok(env.to_vec());
}

pub(crate) fn get_old_info(info: &[u8]) -> VmResult<Vec<u8>> {
    let info_struct: MessageInfo = from_slice(info)?;
    let old_info_struct = MessageInfoV0_13_2 {
        sender: info_struct.sender.to_string(),
        sent_funds: info_struct.sent_funds,
    };

    to_vec(&old_info_struct)
}

pub(crate) fn is_old_instance<A, S, Q>(instance: &mut Instance<A, S, Q>) -> bool
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
{
    instance
        .call_function0("cosmwasm_vm_version_4", &[])
        .is_ok()
}

pub fn call_instantiate<A, S, Q, U>(
    instance: &mut Instance<A, S, Q>,
    env: &Env,
    info: &MessageInfo,
    msg: &[u8],
) -> VmResult<ContractResult<Response<U>>>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
    U: DeserializeOwned + Clone + fmt::Debug + JsonSchema + PartialEq,
{
    let env = to_vec(env)?;
    let info = to_vec(info)?;
    let data = call_instantiate_raw(instance, &env, &info, msg)?;
    let result: ContractResult<Response<U>> = from_slice(&data)?;
    Ok(result)
}

pub fn call_execute<A, S, Q, U>(
    instance: &mut Instance<A, S, Q>,
    env: &Env,
    info: &MessageInfo,
    msg: &[u8],
) -> VmResult<ContractResult<Response<U>>>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
    U: DeserializeOwned + Clone + fmt::Debug + JsonSchema + PartialEq,
{
    let env = to_vec(env)?;
    let info = to_vec(info)?;
    let data = call_execute_raw(instance, &env, &info, msg)?;
    let result: ContractResult<Response<U>> = from_slice(&data)?;
    Ok(result)
}

pub fn call_migrate<A, S, Q, U>(
    instance: &mut Instance<A, S, Q>,
    env: &Env,
    msg: &[u8],
) -> VmResult<ContractResult<Response<U>>>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
    U: DeserializeOwned + Clone + fmt::Debug + JsonSchema + PartialEq,
{
    let env = to_vec(env)?;
    let data = call_migrate_raw(instance, &env, msg)?;
    let result: ContractResult<Response<U>> = from_slice(&data)?;
    Ok(result)
}

pub fn call_sudo<A, S, Q, U>(
    instance: &mut Instance<A, S, Q>,
    env: &Env,
    msg: &[u8],
) -> VmResult<ContractResult<Response<U>>>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
    U: DeserializeOwned + Clone + fmt::Debug + JsonSchema + PartialEq,
{
    let env = to_vec(env)?;
    let data = call_sudo_raw(instance, &env, msg)?;
    let result: ContractResult<Response<U>> = from_slice(&data)?;
    Ok(result)
}

pub fn call_reply<A, S, Q, U>(
    instance: &mut Instance<A, S, Q>,
    env: &Env,
    msg: &Reply,
) -> VmResult<ContractResult<Response<U>>>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
    U: DeserializeOwned + Clone + fmt::Debug + JsonSchema + PartialEq,
{
    let env = to_vec(env)?;
    let msg = to_vec(msg)?;
    let data = call_reply_raw(instance, &env, &msg)?;
    let result: ContractResult<Response<U>> = from_slice(&data)?;
    Ok(result)
}

pub fn call_query<A, S, Q>(
    instance: &mut Instance<A, S, Q>,
    env: &Env,
    msg: &[u8],
) -> VmResult<ContractResult<QueryResponse>>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
{
    let env = to_vec(env)?;
    let data = call_query_raw(instance, &env, msg)?;
    let result: ContractResult<QueryResponse> = from_slice(&data)?;
    // Ensure query response is valid JSON
    if let ContractResult::Ok(binary_response) = &result {
        serde_json::from_slice::<serde_json::Value>(binary_response.as_slice()).map_err(|e| {
            VmError::generic_err(format!("Query response must be valid JSON. {}", e))
        })?;
    }

    Ok(result)
}

/// Calls Wasm export "instantiate" and returns raw data from the contract.
/// The result is length limited to prevent abuse but otherwise unchecked.
pub fn call_instantiate_raw<A, S, Q>(
    instance: &mut Instance<A, S, Q>,
    env: &[u8],
    info: &[u8],
    msg: &[u8],
) -> VmResult<Vec<u8>>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
{
    instance.set_storage_readonly(false);

    if is_old_instance(instance) {
        // this can be called from vm go

        return call_raw(
            instance,
            "init",
            &[&get_old_env(env)?, &get_old_info(info)?, msg],
            MAX_LENGTH_INIT,
        );
    }
    call_raw(instance, "instantiate", &[env, info, msg], MAX_LENGTH_INIT)
}

/// Calls Wasm export "execute" and returns raw data from the contract.
/// The result is length limited to prevent abuse but otherwise unchecked.
pub fn call_execute_raw<A, S, Q>(
    instance: &mut Instance<A, S, Q>,
    env: &[u8],
    info: &[u8],
    msg: &[u8],
) -> VmResult<Vec<u8>>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
{
    instance.set_storage_readonly(false);

    if is_old_instance(instance) {
        // this can be called from vm go
        return call_raw(
            instance,
            "handle",
            &[&get_old_env(env)?, &get_old_info(info)?, msg],
            MAX_LENGTH_EXECUTE,
        );
    }

    call_raw(instance, "execute", &[env, info, msg], MAX_LENGTH_EXECUTE)
}

/// Calls Wasm export "migrate" and returns raw data from the contract.
/// The result is length limited to prevent abuse but otherwise unchecked.
pub fn call_migrate_raw<A, S, Q>(
    instance: &mut Instance<A, S, Q>,
    env: &[u8],
    msg: &[u8],
) -> VmResult<Vec<u8>>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
{
    instance.set_storage_readonly(false);

    if is_old_instance(instance) {
        return call_raw(
            instance,
            "migrate",
            &[&get_old_env(env)?, msg],
            MAX_LENGTH_MIGRATE,
        );
    };

    call_raw(instance, "migrate", &[env, msg], MAX_LENGTH_MIGRATE)
}

/// Calls Wasm export "sudo" and returns raw data from the contract.
/// The result is length limited to prevent abuse but otherwise unchecked.
pub fn call_sudo_raw<A, S, Q>(
    instance: &mut Instance<A, S, Q>,
    env: &[u8],
    msg: &[u8],
) -> VmResult<Vec<u8>>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
{
    instance.set_storage_readonly(false);

    if is_old_instance(instance) {
        return call_raw(
            instance,
            "sudo",
            &[&get_old_env(env)?, msg],
            MAX_LENGTH_SUDO,
        );
    };

    call_raw(instance, "sudo", &[env, msg], MAX_LENGTH_SUDO)
}

/// Calls Wasm export "reply" and returns raw data from the contract.
/// The result is length limited to prevent abuse but otherwise unchecked.
pub fn call_reply_raw<A, S, Q>(
    instance: &mut Instance<A, S, Q>,
    env: &[u8],
    msg: &[u8],
) -> VmResult<Vec<u8>>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
{
    instance.set_storage_readonly(false);

    if is_old_instance(instance) {
        return call_raw(
            instance,
            "reply",
            &[&get_old_env(env)?, msg],
            MAX_LENGTH_SUBCALL_RESPONSE,
        );
    };

    call_raw(instance, "reply", &[env, msg], MAX_LENGTH_SUBCALL_RESPONSE)
}

/// Calls Wasm export "query" and returns raw data from the contract.
/// The result is length limited to prevent abuse but otherwise unchecked.
pub fn call_query_raw<A, S, Q>(
    instance: &mut Instance<A, S, Q>,
    env: &[u8],
    msg: &[u8],
) -> VmResult<Vec<u8>>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
{
    instance.set_storage_readonly(true);

    if is_old_instance(instance) {
        return call_raw(
            instance,
            "query",
            &[&get_old_env(env)?, msg],
            MAX_LENGTH_QUERY,
        );
    };

    call_raw(instance, "query", &[env, msg], MAX_LENGTH_QUERY)
}

/// Calls a function with the given arguments.
/// The exported function must return exactly one result (an offset to the result Region).
pub(crate) fn call_raw<A, S, Q>(
    instance: &mut Instance<A, S, Q>,
    name: &str,
    args: &[&[u8]],
    result_max_length: usize,
) -> VmResult<Vec<u8>>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
{
    let mut arg_region_ptrs = Vec::<Val>::with_capacity(args.len());
    for arg in args {
        let region_ptr = instance.allocate(arg.len())?;
        instance.write_memory(region_ptr, arg)?;
        arg_region_ptrs.push(region_ptr.into());
    }
    let result = instance.call_function1(name, &arg_region_ptrs)?;
    let res_region_ptr = ref_to_u32(&result)?;
    let data = instance.read_memory(res_region_ptr, result_max_length)?;
    // free return value in wasm (arguments were freed in wasm code)
    instance.deallocate(res_region_ptr)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{mock_env, mock_info, mock_instance};
    use cosmwasm_std::{coins, Empty};

    static CONTRACT: &[u8] = include_bytes!("../testdata/hackatom.wasm");

    #[test]
    fn call_instantiate_works() {
        let mut instance = mock_instance(&CONTRACT, &[]);

        // init
        let info = mock_info("creator", &coins(1000, "earth"));
        let msg = br#"{"verifier": "verifies", "beneficiary": "benefits"}"#;
        call_instantiate::<_, _, _, Empty>(&mut instance, &mock_env(), &info, msg)
            .unwrap()
            .unwrap();
    }

    #[test]
    fn call_execute_works() {
        let mut instance = mock_instance(&CONTRACT, &[]);

        // init
        let info = mock_info("creator", &coins(1000, "earth"));
        let msg = br#"{"verifier": "verifies", "beneficiary": "benefits"}"#;
        call_instantiate::<_, _, _, Empty>(&mut instance, &mock_env(), &info, msg)
            .unwrap()
            .unwrap();

        // execute
        let info = mock_info("verifies", &coins(15, "earth"));
        let msg = br#"{"release":{}}"#;
        call_execute::<_, _, _, Empty>(&mut instance, &mock_env(), &info, msg)
            .unwrap()
            .unwrap();
    }

    #[test]
    fn call_migrate_works() {
        let mut instance = mock_instance(&CONTRACT, &[]);

        // init
        let info = mock_info("creator", &coins(1000, "earth"));
        let msg = br#"{"verifier": "verifies", "beneficiary": "benefits"}"#;
        call_instantiate::<_, _, _, Empty>(&mut instance, &mock_env(), &info, msg)
            .unwrap()
            .unwrap();

        // change the verifier via migrate
        let msg = br#"{"verifier": "someone else"}"#;
        let _res = call_migrate::<_, _, _, Empty>(&mut instance, &mock_env(), msg);

        // query the new_verifier with verifier
        let msg = br#"{"verifier":{}}"#;
        let contract_result = call_query(&mut instance, &mock_env(), msg).unwrap();
        let query_response = contract_result.unwrap();
        assert_eq!(
            query_response.as_slice(),
            b"{\"verifier\":\"someone else\"}"
        );
    }

    #[test]
    fn call_query_works() {
        let mut instance = mock_instance(&CONTRACT, &[]);

        // init
        let info = mock_info("creator", &coins(1000, "earth"));
        let msg = br#"{"verifier": "verifies", "beneficiary": "benefits"}"#;
        call_instantiate::<_, _, _, Empty>(&mut instance, &mock_env(), &info, msg)
            .unwrap()
            .unwrap();

        // query
        let msg = br#"{"verifier":{}}"#;
        let contract_result = call_query(&mut instance, &mock_env(), msg).unwrap();
        let query_response = contract_result.unwrap();
        assert_eq!(query_response.as_slice(), b"{\"verifier\":\"verifies\"}");
    }
}

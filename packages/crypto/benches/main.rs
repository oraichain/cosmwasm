use criterion::{criterion_group, criterion_main, Criterion, PlottingBackend};
use std::time::Duration;

use english_numbers::convert_no_fmt;
use hex_literal::hex;
use serde::Deserialize;

// Crypto stuff
use digest::Digest;
use k256::ecdsa::SigningKey; // type alias
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;

use cosmwasm_crypto::{
    curve_hash, ed25519_batch_verify, ed25519_verify, groth16_verify, secp256k1_recover_pubkey,
    secp256k1_verify, Poseidon,
};
use std::cmp::min;

const COSMOS_SECP256K1_MSG_HEX: &str = "0a93010a90010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e6412700a2d636f736d6f7331706b707472653766646b6c366766727a6c65736a6a766878686c63337234676d6d6b38727336122d636f736d6f7331717970717870713971637273737a673270767871367273307a716733797963356c7a763778751a100a0575636f736d12073132333435363712650a4e0a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21034f04181eeba35391b858633a765c4a0c189697b40d216354d50890d350c7029012040a02080112130a0d0a0575636f736d12043230303010c09a0c1a0c73696d642d74657374696e672001";
const COSMOS_SECP256K1_SIGNATURE_HEX: &str = "c9dd20e07464d3a688ff4b710b1fbc027e495e797cfa0b4804da2ed117959227772de059808f765aa29b8f92edf30f4c2c5a438e30d3fe6897daa7141e3ce6f9";
const COSMOS_SECP256K1_PUBKEY_BASE64: &str = "A08EGB7ro1ORuFhjOnZcSgwYlpe0DSFjVNUIkNNQxwKQ";

// TEST 3 test vector from https://tools.ietf.org/html/rfc8032#section-7.1
const COSMOS_ED25519_MSG_HEX: &str = "af82";
const COSMOS_ED25519_SIGNATURE_HEX: &str = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
const COSMOS_ED25519_PUBLIC_KEY_HEX: &str =
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";

// Test data from https://tools.ietf.org/html/rfc8032#section-7.1
const COSMOS_ED25519_TESTS_JSON: &str = "./testdata/ed25519_tests.json";

// Test poseidon
const COMMITMENT: &str = "84d6bdcfd953993012f08970d9c9b472d96114b4edc69481968cafc07877381c";

// Test groth16 verify
const PUBLIC_INPUT:&str="b7a08d5962f1dc5778f9f2385c291ce6f76f9b075e028e6500f327203bebc61f5219025541ad12054aaf6c0ee8c5ae09f23b693068a9cc80fd960f666cd65121e0fb95195eb23c3c65d7df44a7adf83871ec0380189d3e757417765d51ae0d2a";
const PROOF : &str="220db2e21ce3a4cb15bc70bdea9a40bfaf17bf236b8a05a298506d1b7fe2c4aeb62795a4dc410cc768fbcf0956155e4a71fb6785c6914d3b6ea9de5fa7b4992591ffbaf98c58474cd062ab9a813fa05a17aef87479a4e5c4d8e8b5e44b0d01869241daef38dd52074a0677564e890e05761ac36c6c9ff23d8356b9ad6d9aeb2f";
const VK:&str="a8d29ea40629be762f2a12bda7cc45b998a34c43a96c4c6744c8c7a900e8f80a5eece6fa5771489cb0306f499ad91a33d0159f29786332d782db870a0980440aa1225ad23c0e476c7d36b796e6a9b50240841b4be955d13ea54dd8da01128e0cf92094b459ff882780abdf3e1784c06df6c85c0006fd7f2597e3e9052d9215274f08fc4f94dc8129f29a578dc17f5ea60ea85d2c88a78294b792dbf2fa8d30973b80ca6b567463b690b8b3a8f70eb6468227358e5f316eb8150a92152b753519c4ca827fec17f7283d15228767b56b736ec9498f39fe5b511a8af503b63a19970400000000000000b9c86bbe3e5ef3490d5db478be0a7933934e4b5a148e2c01602b475c83e2500891dc44a6fe2f331da9b66f3562398a762677f7b7c95d3a82a9698e0cf6212128d6eb27a3f11abb52a98a509bf1502f0947e9ab9c1d72a086140c0d316866d624c22a69f8dfb5957e35d8d3d350b3c83ee95e8897c7b76d41881683d2561cd919";

#[derive(Deserialize, Debug)]
struct Encoded {
    #[serde(rename = "privkey")]
    #[allow(dead_code)]
    private_key: String,
    #[serde(rename = "pubkey")]
    public_key: String,
    message: String,
    signature: String,
}

fn read_cosmos_sigs() -> Vec<Encoded> {
    use std::fs::File;
    use std::io::BufReader;

    // Open the file in read-only mode with buffer.
    let file = File::open(COSMOS_ED25519_TESTS_JSON).unwrap();
    let reader = BufReader::new(file);

    serde_json::from_reader(reader).unwrap()
}

#[allow(clippy::type_complexity)]
fn read_decode_cosmos_sigs() -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let codes = read_cosmos_sigs();

    let mut messages: Vec<Vec<u8>> = vec![];
    let mut signatures: Vec<Vec<u8>> = vec![];
    let mut public_keys: Vec<Vec<u8>> = vec![];

    for encoded in codes {
        let message = hex::decode(&encoded.message).unwrap();
        messages.push(message);

        let signature = hex::decode(&encoded.signature).unwrap();
        signatures.push(signature);

        let public_key = hex::decode(&encoded.public_key).unwrap();
        public_keys.push(public_key);
    }

    (messages, signatures, public_keys)
}

fn bench_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("Crypto");

    group.bench_function("secp256k1_verify", |b| {
        let message = hex::decode(COSMOS_SECP256K1_MSG_HEX).unwrap();
        let message_hash = Sha256::digest(message);
        let signature = hex::decode(COSMOS_SECP256K1_SIGNATURE_HEX).unwrap();
        let public_key = base64::decode(COSMOS_SECP256K1_PUBKEY_BASE64).unwrap();
        b.iter(|| {
            assert!(secp256k1_verify(&message_hash, &signature, &public_key).unwrap());
        });
    });

    group.bench_function("curve_hash", |b| {
        let message = hex::decode(COSMOS_SECP256K1_MSG_HEX).unwrap();
        let message_hash = Sha256::digest(&message);
        b.iter(|| {
            assert!(!curve_hash(&message_hash).is_empty());
        });
    });

    group.bench_function("poseidon_hash", |b| {
        let commitment_hash = hex::decode(COMMITMENT).unwrap();
        let poseidon = Poseidon::new();
        b.iter(|| {
            assert!(poseidon.hash(&[&commitment_hash, &commitment_hash]).is_ok());
        });
    });

    group.bench_function("groth16_verify", |b| {
        let input = hex::decode(PUBLIC_INPUT).unwrap();
        let proof = hex::decode(PROOF).unwrap();
        let vk = hex::decode(VK).unwrap();
        b.iter(|| {
            assert!(groth16_verify(&input, &proof, &vk).unwrap());
        });
    });

    group.bench_function("secp256k1_recover_pubkey", |b| {
        let message_hash =
            hex!("82ff40c0a986c6a5cfad4ddf4c3aa6996f1a7837f9c398e17e5de5cbd5a12b28");
        let private_key =
            hex!("3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1");
        let r_s = hex!("99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66");
        let recovery_param: u8 = 0;

        let expected = SigningKey::from_bytes(&private_key)
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        b.iter(|| {
            let pubkey = secp256k1_recover_pubkey(&message_hash, &r_s, recovery_param).unwrap();
            assert_eq!(pubkey, expected);
        });
    });

    group.bench_function("ed25519_verify", |b| {
        let message = hex::decode(COSMOS_ED25519_MSG_HEX).unwrap();
        let signature = hex::decode(COSMOS_ED25519_SIGNATURE_HEX).unwrap();
        let public_key = hex::decode(COSMOS_ED25519_PUBLIC_KEY_HEX).unwrap();
        b.iter(|| {
            assert!(ed25519_verify(&message, &signature, &public_key).unwrap());
        });
    });

    // Ed25519 batch verification of different batch lengths
    {
        let (messages, signatures, public_keys) = read_decode_cosmos_sigs();
        let messages: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        let signatures: Vec<&[u8]> = signatures.iter().map(|m| m.as_slice()).collect();
        let public_keys: Vec<&[u8]> = public_keys.iter().map(|m| m.as_slice()).collect();

        for n in (1..=min(messages.len(), 10)).step_by(2) {
            group.bench_function(
                format!("ed25519_batch_verify_{}", convert_no_fmt(n as i64)),
                |b| {
                    b.iter(|| {
                        assert!(ed25519_batch_verify(
                            &messages[..n],
                            &signatures[..n],
                            &public_keys[..n]
                        )
                        .unwrap());
                    });
                },
            );
        }
    }

    // Ed25519 batch verification of different batch lengths, with the same pubkey
    {
        //FIXME: Use different messages / signatures
        let messages = [hex::decode(COSMOS_ED25519_MSG_HEX).unwrap()];
        let signatures = [hex::decode(COSMOS_ED25519_SIGNATURE_HEX).unwrap()];
        let public_keys = [hex::decode(COSMOS_ED25519_PUBLIC_KEY_HEX).unwrap()];

        let messages: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        let signatures: Vec<&[u8]> = signatures.iter().map(|m| m.as_slice()).collect();
        let public_keys: Vec<&[u8]> = public_keys.iter().map(|m| m.as_slice()).collect();

        for n in (1..10).step_by(2) {
            group.bench_function(
                format!(
                    "ed25519_batch_verify_one_pubkey_{}",
                    convert_no_fmt(n as i64)
                ),
                |b| {
                    b.iter(|| {
                        assert!(ed25519_batch_verify(
                            &messages.repeat(n),
                            &signatures.repeat(n),
                            &public_keys
                        )
                        .unwrap());
                    });
                },
            );
        }
    }

    group.finish();
}

fn make_config() -> Criterion {
    Criterion::default()
        .plotting_backend(PlottingBackend::Plotters)
        .without_plots()
        .measurement_time(Duration::new(10, 0))
        .sample_size(12)
}

criterion_group!(
    name = crypto;
    config = make_config();
    targets = bench_crypto
);
criterion_main!(crypto);

use std::fs::File;
use std::io::{self, BufReader, BufWriter};

use serde_derive::{Deserialize, Serialize};

const KEYPAIR_FILE: &str = "keypairs.json";
const NUM_KEYPAIRS: usize = 9;
mod bls;

#[derive(Serialize, Deserialize)]
struct SerializableBlsKeypair {
    secret: Vec<u8>,
    public: Vec<u8>,
}

fn main() {
    let mut keypairs = Vec::new();

    let loaded_keypairs = match load_keypairs() {
        Ok(keypairs) => keypairs,
        Err(e) => {
            println!("Error loading keypairs: {}", e);
            Vec::new()
        }
    };

    if loaded_keypairs.is_empty() {
        println!("No keypairs found, generating new ones");
    } else {
        println!("Loaded keypairs from file");
        aggregate_expand_and_check(&loaded_keypairs).unwrap();
        return;
    }
    loop {
        for _ in 0..NUM_KEYPAIRS {
            keypairs.push(bls::BlsKeypair::new());
        }

        for keypair in &keypairs {
            println!("Pubkey: {}", b58::encode(keypair.pubkey()));
        }
        aggregate_expand_and_check(&keypairs).unwrap();
    }
}

pub fn aggregate_expand_and_check(keypairs: &Vec<bls::BlsKeypair>) -> io::Result<()> {
    println!("Aggregating keypairs...");
    let aggregate_pubkey = bls::aggregate(
        &keypairs
            .iter()
            .map(|k| k.pubkey())
            .collect::<Vec<&[u8; 64]>>(),
    )
    .unwrap();
    println!("Aggregate pubkey: {}", b58::encode(&aggregate_pubkey));
    let expanded_pubkey = bls::expand_pubkey(&aggregate_pubkey).unwrap();
    let expanded_pubkey_with_appended_bytes =
        bls::expand_pubkey_with_appended_bytes(&aggregate_pubkey).unwrap();
    println!("Expanded pubkey: {}", b58::encode(&expanded_pubkey));
    println!(
        "Expanded pubkey with appended bytes: {}",
        b58::encode(&expanded_pubkey_with_appended_bytes)
    );
    if expanded_pubkey != expanded_pubkey_with_appended_bytes {
        println!("Expanded pubkeys are different");
        save_keypairs(&keypairs).unwrap();
        panic!("Expanded pubkeys are different");
    }
    Ok(())
}
fn save_keypairs(keypairs: &Vec<bls::BlsKeypair>) -> io::Result<()> {
    let file = File::create(KEYPAIR_FILE)?;
    let writer = BufWriter::new(file);
    let serializable_keypairs: Vec<SerializableBlsKeypair> = keypairs
        .iter()
        .map(|keypair| SerializableBlsKeypair {
            secret: keypair.insecure_clone().secret.0.to_vec(),
            public: keypair.pubkey().to_vec(),
        })
        .collect();
    serde_json::to_writer_pretty(writer, &serializable_keypairs)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Serialization error: {}", e)))?;
    Ok(())
}

fn load_keypairs() -> io::Result<Vec<bls::BlsKeypair>> {
    let file = File::open(KEYPAIR_FILE)?;
    let reader = BufReader::new(file);
    let serializable_keypairs: Vec<SerializableBlsKeypair> = serde_json::from_reader(reader)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Deserialization error: {}", e),
            )
        })?;
    Ok(serializable_keypairs
        .iter()
        .map(|kp| bls::BlsKeypair {
            secret: {
                let secret_arr: [u8; 32] = kp
                    .secret
                    .as_slice()
                    .try_into()
                    .expect("secret key is not 32 bytes");
                solana_alt_bn128_bls::privkey::PrivKey(secret_arr)
            },
            public: {
                let arr = kp.public.as_slice();
                let pubkey: [u8; 64] = arr.try_into().expect("public key is not 64 bytes");
                pubkey
            },
        })
        .collect())
}

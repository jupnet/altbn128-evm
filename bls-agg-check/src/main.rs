use std::fs::File;
use std::io::{self, BufReader, BufWriter};

use bls_agg_check::AltBn128;
use serde_derive::{Deserialize, Serialize};

const KEYPAIR_FILE: &str = "keypairs.json";
const NUM_KEYPAIRS: usize = 9;
mod bls;
mod lib;

#[derive(Serialize, Deserialize)]
struct SerializableBlsKeypair {
    secret: Vec<u8>,
    public: Vec<u8>,
}

const TEST_HASHES: [[u8; 32]; 5] = [
    [
        99, 75, 169, 192, 94, 237, 11, 44, 252, 81, 193, 179, 11, 67, 32, 228, 253, 200, 165, 211,
        149, 138, 149, 147, 23, 229, 118, 216, 17, 219, 205, 127,
    ],
    [
        97, 231, 104, 132, 91, 22, 133, 122, 67, 112, 254, 210, 129, 246, 95, 36, 78, 253, 158,
        233, 85, 72, 122, 52, 20, 204, 13, 96, 205, 117, 149, 54,
    ],
    [
        27, 119, 169, 153, 242, 238, 109, 253, 236, 44, 54, 176, 6, 5, 246, 39, 23, 216, 242, 205,
        45, 249, 184, 144, 127, 136, 95, 137, 164, 200, 216, 181,
    ],
    [
        245, 92, 173, 65, 44, 156, 90, 81, 35, 1, 184, 9, 194, 40, 189, 139, 15, 161, 133, 58, 28,
        243, 138, 20, 174, 60, 93, 126, 195, 0, 24, 48,
    ],
    [
        91, 245, 247, 225, 222, 131, 167, 6, 161, 154, 60, 86, 165, 210, 33, 87, 216, 232, 176,
        127, 162, 220, 239, 136, 186, 230, 252, 36, 7, 94, 120, 33,
    ],
];

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
        if let Err(e) = aggregate_expand_and_check(&loaded_keypairs) {
            println!("Error: {}", e);
        }
        run_test_cases(&loaded_keypairs).unwrap();
        return;
    }
    loop {
        for _ in 0..NUM_KEYPAIRS {
            keypairs.push(bls::BlsKeypair::new());
        }

        for keypair in &keypairs {
            println!("Pubkey: {}", b58::encode(keypair.pubkey()));
        }
        if let Err(e) = aggregate_expand_and_check(&keypairs) {
            println!("Error: {}", e);
            return;
        }
    }
}

pub fn run_test_cases(keypairs: &Vec<bls::BlsKeypair>) -> io::Result<()> {
    let aggregate_pubkey = bls::aggregate(
        &keypairs
            .iter()
            .map(|k| k.pubkey())
            .collect::<Vec<&[u8; 64]>>(),
    )
    .unwrap();
    let expanded_pubkey = bls::expand_pubkey(&aggregate_pubkey).unwrap();
    let expanded_pubkey_with_appended_bytes =
        bls::expand_pubkey_with_appended_bytes(&aggregate_pubkey).unwrap();
    println!("");
    println!("Expanded pubkey: {}", b58::encode(&expanded_pubkey));
    println!("Expanded pubkey as hex: {}", hex::encode(&expanded_pubkey));
    println!("");
    println!(
        "Expanded pubkey with appended bytes: {}",
        b58::encode(&expanded_pubkey_with_appended_bytes)
    );
    println!(
        "Expanded pubkey with appended bytes as hex: {}",
        hex::encode(&expanded_pubkey_with_appended_bytes)
    );

    for hash in TEST_HASHES {
        println!("================================================");
        println!("Hash: {:?}", b58::encode(&hash));
        println!("Hash as hex: {}", hex::encode(&hash));
        println!("");
        let mut signatures = Vec::new();
        for keypair in keypairs {
            let signature = keypair.sign_message(&hash).unwrap();
            signatures.push(signature);
        }
        let aggregate_signature = bls::aggregate_signatures(&signatures).unwrap();
        println!(
            "Aggregate signature: {:?}",
            b58::encode(&aggregate_signature)
        );
        println!(
            "Aggregate signature as hex: {}",
            hex::encode(&aggregate_signature)
        );
        println!("");
        let expanded_signature = bls::expand_signature(&aggregate_signature).unwrap();
        println!("Expanded signature: {:?}", b58::encode(&expanded_signature));
        println!(
            "Expanded signature as hex: {}",
            hex::encode(&expanded_signature)
        );
        println!("");
        let result = bls::verify_signature(&aggregate_pubkey, &aggregate_signature, &hash);
        let verification_result = if result.is_err() {
            println!("Invalid signature");
            false
        } else {
            println!("Valid signature");
            true
        };
        println!("");
        println!("Checking AltBn128 verification with expanded pubkey with appended bytes...");
        let altbn128_result = check_altbn128(
            &expanded_pubkey_with_appended_bytes,
            &expanded_signature,
            &hash,
            verification_result,
        );
        if altbn128_result.is_err() {
            let error = altbn128_result.unwrap_err();
            println!("Error: {}", error);
        }

        println!("");
        println!("Checking AltBn128 verification with expanded pubkey...");
        let altbn128_result = check_altbn128(
            &expanded_pubkey,
            &expanded_signature,
            &hash,
            verification_result,
        );
        if altbn128_result.is_err() {
            let error = altbn128_result.unwrap_err();
            println!("Error: {}", error);
        }
        println!("");
        println!("================================================");
    }
    Ok(())
}

pub fn check_altbn128(
    expanded_pubkey: &Vec<u8>,
    expanded_signature: &Vec<u8>,
    hash: &[u8; 32],
    verification_result: bool,
) -> io::Result<()> {
    // Check if expanded pubkey and signature have correct lengths
    let pubkey_len = expanded_pubkey.len();
    let sig_len = expanded_signature.len();
    let altbn128 = AltBn128::new();
    // AltBn128 expects 128-byte pubkey and 64-byte signature
    if pubkey_len >= 128 && sig_len >= 64 {
        // Take the first 128 bytes of pubkey and first 64 bytes of signature
        let pubkey_slice = &expanded_pubkey[..128];
        let sig_slice = &expanded_signature[..64];

        match altbn128.verify_signature(&hash, pubkey_slice, sig_slice) {
            Ok(valid) => {
                println!(
                    "AltBn128 verification: {}",
                    if valid { "✅ VALID" } else { "❌ INVALID" }
                );

                // Compare results
                if verification_result == valid {
                    println!("Result consistency: ✅ MATCH (BLS and AltBn128 agree)");
                } else {
                    println!(
                        "Result consistency: ⚠️  MISMATCH (BLS: {}, AltBn128: {})",
                        verification_result, valid
                    );
                }
                return Ok(());
            }
            Err(e) => {
                println!("AltBn128 verification error: {}", e);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "AltBn128 verification error",
                ));
            }
        }
    } else {
        println!("❌ Cannot test: Invalid key lengths (need 128-byte pubkey, 64-byte signature)");
        if pubkey_len < 128 {
            println!("   Pubkey too short: {} < 128 bytes", pubkey_len);
            return Err(io::Error::new(io::ErrorKind::Other, "Pubkey too short"));
        }
        if sig_len < 64 {
            println!("   Signature too short: {} < 64 bytes", sig_len);
            return Err(io::Error::new(io::ErrorKind::Other, "Signature too short"));
        }
    }
    return Err(io::Error::new(io::ErrorKind::Other, "Invalid key lengths"));
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
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Expanded pubkeys are different",
        ));
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

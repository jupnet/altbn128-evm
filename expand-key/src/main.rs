use solana_alt_bn128_bls::{
    G1CompressedPoint, G1Point, G2CompressedPoint, G2Point, Sha256Normalized,
};

fn main() -> anyhow::Result<()> {
    //65HTQ9s2GdhSMyeb7ANmY6r3wLZTVqTBedEoVgKBSzVHnimD5Py55BtHFm1R6NkzUKWUm2MaB97oRhvy6D8WQqH
    let aggregated_pubkey: [u8; 64] = [
        4, 96, 32, 225, 173, 128, 148, 215, 152, 56, 238, 248, 195, 228, 44, 138, 21, 208, 31, 229,
        104, 129, 192, 248, 126, 97, 138, 90, 1, 25, 81, 140, 38, 105, 5, 179, 141, 224, 125, 135,
        252, 219, 97, 38, 24, 97, 91, 37, 247, 26, 126, 232, 228, 119, 197, 43, 153, 250, 38, 166,
        213, 208, 46, 228,
    ];

    // 7gcHBDmGcA3WGfNNBYRVxS8vGAAAv1yB9NsGvAdhpBux
    let hash = [
        99, 75, 169, 192, 94, 237, 11, 44, 252, 81, 193, 179, 11, 67, 32, 228, 253, 200, 165, 211,
        149, 138, 149, 147, 23, 229, 118, 216, 17, 219, 205, 127,
    ];

    // 9rEJqrPQ3eVxyQWBFWHiAdTx1hJ7FZ1FyMvJgWyTQC9G
    let signature: [u8; 32] = [
        131, 122, 0, 133, 100, 25, 106, 107, 172, 193, 145, 7, 1, 20, 100, 47, 72, 97, 196, 230,
        193, 60, 68, 160, 119, 64, 197, 40, 187, 8, 12, 99,
    ];
    verify_and_print(&aggregated_pubkey, &signature, &hash)?;

    // The following fails when expanded and verified on EVM contract

    // 2rDqbvCW1kq8XTJKNPtPvrdqxmMAxuQD4GBRdRADjZnL
    let hash = [
        27, 119, 169, 153, 242, 238, 109, 253, 236, 44, 54, 176, 6, 5, 246, 39, 23, 216, 242, 205,
        45, 249, 184, 144, 127, 136, 95, 137, 164, 200, 216, 181,
    ];

    // CpBiAQGdCt9can81yaquduDDCmV5EQEQfHvi3oy5Xgxd
    let signature: [u8; 32] = [
        175, 134, 246, 181, 58, 216, 234, 20, 138, 35, 80, 68, 172, 247, 46, 247, 182, 198, 210,
        151, 77, 85, 3, 222, 50, 132, 254, 104, 135, 69, 12, 134,
    ];
    verify_and_print(&aggregated_pubkey, &signature, &hash)?;

    // HWnrHbijXADKMQSe2JfkgtKvgCezjsrybG7UZBWJo8Uw
    let hash = [
        245, 92, 173, 65, 44, 156, 90, 81, 35, 1, 184, 9, 194, 40, 189, 139, 15, 161, 133, 58, 28,
        243, 138, 20, 174, 60, 93, 126, 195, 0, 24, 48,
    ];

    // Brg13sWeMAxu1jjqWz2qQ8p5RHwtpuq4VzPcfvcuPinS
    let signature: [u8; 32] = [
        161, 78, 109, 100, 110, 246, 90, 211, 176, 233, 181, 202, 21, 146, 123, 97, 213, 205, 245,
        99, 138, 151, 201, 4, 160, 161, 12, 246, 229, 29, 109, 223,
    ];
    verify_and_print(&aggregated_pubkey, &signature, &hash)?;

    // 7BydtqZa1EpLZtBQJcopSKUmYFNbVP74cxkvYK3o5FVJ
    let hash = [
        91, 245, 247, 225, 222, 131, 167, 6, 161, 154, 60, 86, 165, 210, 33, 87, 216, 232, 176,
        127, 162, 220, 239, 136, 186, 230, 252, 36, 7, 94, 120, 33,
    ];

    // AcyYrRqQkNT2CmRqt4zJ8qQdBSNCHeCoryabvyeXKkZ1
    let signature: [u8; 32] = [
        142, 240, 115, 117, 133, 131, 169, 117, 27, 120, 16, 240, 185, 222, 212, 126, 61, 190, 167,
        247, 113, 219, 39, 89, 120, 215, 226, 161, 112, 173, 41, 156,
    ];
    verify_and_print(&aggregated_pubkey, &signature, &hash)?;

    Ok(())
}

fn verify_and_print(
    aggregated_pubkey: &[u8; 64],
    signature: &[u8; 32],
    hash: &[u8; 32],
) -> anyhow::Result<()> {
    let result = match verify(&aggregated_pubkey, signature, hash) {
        Ok(_) => true,
        Err(e) => {
            println!("Error: {:?}", e);
            false
        }
    };

    print_result(&aggregated_pubkey, signature, hash, result)?;
    Ok(())
}

fn print_result(
    aggregated_pubkey: &[u8; 64],
    signature: &[u8; 32],
    hash: &[u8; 32],
    result: bool,
) -> anyhow::Result<()> {
    println!("================================================");
    println!("Signature verified: {}", result);
    println!("");
    println!("Hash: {:?}", b58::encode(hash));
    println!("Hash in hex: {:?}", hex::encode(hash));
    println!("");
    println!("Aggregated pubkey: {:?}", b58::encode(aggregated_pubkey));
    println!("");
    let expanded_pubkey = expand_evm_pubkey(&aggregated_pubkey)?;
    println!(
        "Expanded pubkey in b58: {:?}",
        b58::encode(&expanded_pubkey)
    );
    println!("");
    println!("Expanded pubkey in hex: {:?}", hex::encode(expanded_pubkey));
    println!("");
    println!("Aggregated signature: {:?}", b58::encode(signature));
    println!("");
    let expanded_signature = expand_evm_signature(&signature)?;
    println!(
        "Expanded signature in b58: {:?}",
        b58::encode(&expanded_signature)
    );
    println!("");
    println!(
        "Expanded signature in hex: {:?}",
        hex::encode(expanded_signature)
    );
    println!("");
    Ok(())
}

fn verify(
    aggregated_pubkey: &[u8; 64],
    signature: &[u8; 32],
    hash: &[u8; 32],
) -> anyhow::Result<()> {
    let agg_pubkey = G2Point::try_from(G2CompressedPoint(*aggregated_pubkey))
        .map_err(|e| anyhow::anyhow!("Failed to convert to G2Point: {:?}", e))?;
    let signature = G1CompressedPoint(*signature);

    agg_pubkey
        .verify_signature::<Sha256Normalized, _, _>(signature, hash)
        .map_err(|e| anyhow::anyhow!("Invalid signature: {:?}", e))?;
    Ok(())
}

/// Aggregates multiple EVM BLS pubkeys
/// For EVM, we need to aggregate the pubkeys normally first, then adjust the format
fn expand_evm_pubkey(aggregated_pubkey: &[u8; 64]) -> anyhow::Result<Vec<u8>> {
    // First decode and aggregate pubkeys normally

    // For EVM, we need to convert to G2Point and back, but preserve the first 64 bytes
    let mut g2_point = G2Point::try_from(G2CompressedPoint(*aggregated_pubkey))
        .map_err(|e| anyhow::anyhow!("Failed to convert to G2Point: {:?}", e))?;

    // Overwrite the first 64 bytes with the original aggregated pubkey bytes
    g2_point.0[..64].copy_from_slice(aggregated_pubkey.as_ref());

    // Return both the original BlsPubkey and the expanded G2Point bytes
    Ok(g2_point.0.to_vec())
}

/// Expands a BLS signature for EVM (from 32 bytes compressed to 64 bytes uncompressed G1 point)
fn expand_evm_signature(signature: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    let g1_point = G1Point::try_from(&G1CompressedPoint(*signature))
        .map_err(|e| anyhow::anyhow!("Failed to convert to G1Point: {:?}", e))?;

    Ok(g1_point.0.to_vec())
}

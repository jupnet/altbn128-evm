use dashu_int::UBig;
use num_traits::ops::checked::CheckedAdd;
use rand::{RngCore, rngs::OsRng};
use solana_alt_bn128_bls::{
    BLSSignature, G1CompressedPoint, G1Point, G2_MINUS_ONE, G2CompressedPoint, G2Point,
    HashToCurve, MODULUS, NORMALIZE_MODULUS, PrivKey, Sha256Normalized,
};
use solana_bn254::{compression::prelude::alt_bn128_g1_decompress, prelude::alt_bn128_pairing};
use std::ops::Add;

pub const BLS_PUBKEY_BYTES: usize = 64;

pub struct BlsKeypair {
    pub secret: PrivKey,
    pub public: [u8; BLS_PUBKEY_BYTES],
}

impl Default for BlsKeypair {
    fn default() -> Self {
        Self::new()
    }
}

impl BlsKeypair {
    pub fn new() -> Self {
        Self::try_new().expect("BLS keypair generation failed")
    }

    pub fn try_new() -> Result<Self, anyhow::Error> {
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let scalar = UBig::from_be_bytes(&seed);
        #[allow(clippy::arithmetic_side_effects)]
        let reduced_scalar = &scalar % &MODULUS;

        let reduced_bytes = reduced_scalar.to_be_bytes();
        let mut sk_bytes = [0u8; 32];
        #[allow(clippy::arithmetic_side_effects)]
        sk_bytes[32 - reduced_bytes.len()..].copy_from_slice(&reduced_bytes);

        let secret = PrivKey(sk_bytes);

        let public_g2 = G2CompressedPoint::try_from(&secret)
            .map_err(|_| anyhow::anyhow!("Secret key reconstruction failed"))?;

        let public = public_g2.0;
        Ok(Self { secret, public })
    }

    pub fn pubkey(&self) -> &[u8; 64] {
        &self.public
    }

    pub fn sign_message(&self, message: &[u8]) -> Result<[u8; 32], anyhow::Error> {
        let signature_g1 = self
            .secret
            .sign::<Sha256Normalized, _>(&message)
            .map_err(|_| anyhow::anyhow!("Signing failed"))?;

        let g1_compressed = G1CompressedPoint::try_from(signature_g1)
            .map_err(|_| anyhow::anyhow!("Serialization failed"))?;

        Ok(g1_compressed.0)
    }

    pub fn insecure_clone(&self) -> Self {
        let secret = PrivKey(self.secret.0);

        Self {
            secret,
            public: self.public,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        if bytes.len() != BLS_PUBKEY_BYTES + 32 {
            return Err(anyhow::anyhow!("Deserialization failed"));
        }
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&bytes[0..32]);

        let mut public_bytes = [0u8; BLS_PUBKEY_BYTES];
        public_bytes.copy_from_slice(&bytes[32..]);

        let secret = PrivKey(secret_bytes);
        let public = public_bytes;

        Ok(Self { secret, public })
    }
}

pub fn aggregate(pubkeys: &[&[u8; 64]]) -> Result<[u8; 64], anyhow::Error> {
    if pubkeys.is_empty() {
        return Err(anyhow::anyhow!("Invalid public key"));
    }

    let mut points = Vec::with_capacity(pubkeys.len());
    for pk in pubkeys {
        let g2_compressed = {
            let mut arr = [0u8; BLS_PUBKEY_BYTES];
            arr.copy_from_slice(pk.as_ref());
            G2CompressedPoint(arr)
        };
        let p =
            G2Point::try_from(g2_compressed).map_err(|_| anyhow::anyhow!("Invalid public key"))?;
        points.push(p);
    }

    let mut agg = points[0].clone();
    for point in points.into_iter().skip(1) {
        agg = agg
            .checked_add(&point)
            .ok_or(anyhow::anyhow!("Invalid public key"))?;
    }

    let agg_compressed =
        G2CompressedPoint::try_from(&agg).map_err(|_| anyhow::anyhow!("Serialization failed"))?;

    Ok(agg_compressed.0)
}

pub fn aggregate_signatures(signatures: &[[u8; 32]]) -> Result<[u8; 32], anyhow::Error> {
    if signatures.is_empty() {
        return Err(anyhow::anyhow!("Invalid signature"));
    }

    let mut points = Vec::with_capacity(signatures.len());
    for sig in signatures {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(sig.as_ref());
        let g1_comp = G1CompressedPoint(arr);
        let g1 = G1Point::try_from(&g1_comp).map_err(|_| anyhow::anyhow!("Invalid signature"))?;
        points.push(g1);
    }

    let mut agg = points[0].clone();
    for point in points.into_iter().skip(1) {
        agg = agg.add(point);
    }

    let agg_compressed =
        G1CompressedPoint::try_from(agg).map_err(|_| anyhow::anyhow!("Invalid signature"))?;

    Ok(agg_compressed.0)
}

pub fn expand_pubkey_with_appended_bytes(aggregated_pubkey: &[u8; 64]) -> anyhow::Result<Vec<u8>> {
    // First decode and aggregate pubkeys normally

    // For EVM, we need to convert to G2Point and back, but preserve the first 64 bytes
    let mut g2_point = G2Point::try_from(G2CompressedPoint(*aggregated_pubkey))
        .map_err(|e| anyhow::anyhow!("Failed to convert to G2Point: {:?}", e))?;

    // Overwrite the first 64 bytes with the original aggregated pubkey bytes
    g2_point.0[..64].copy_from_slice(aggregated_pubkey.as_ref());

    // Return both the original BlsPubkey and the expanded G2Point bytes
    Ok(g2_point.0.to_vec())
}

pub fn expand_pubkey(aggregated_pubkey: &[u8; 64]) -> anyhow::Result<Vec<u8>> {
    // First decode and aggregate pubkeys normally

    // For EVM, we need to convert to G2Point and back, but preserve the first 64 bytes
    let g2_point = G2Point::try_from(G2CompressedPoint(*aggregated_pubkey))
        .map_err(|e| anyhow::anyhow!("Failed to convert to G2Point: {:?}", e))?;

    // Return both the original BlsPubkey and the expanded G2Point bytes
    Ok(g2_point.0.to_vec())
}

pub fn verify_signature(
    aggregated_pubkey: &[u8; 64],
    signature: &[u8; 32],
    hash: &[u8; 32],
) -> anyhow::Result<()> {
    let agg_pubkey = G2Point::try_from(G2CompressedPoint(*aggregated_pubkey))
        .map_err(|e| anyhow::anyhow!("Failed to convert to G2Point: {:?}", e))?;
    let signature = G1CompressedPoint(*signature);
    println!("agg_pubkey: {}", b58::encode(&agg_pubkey.0));
    print!("");
    println!("signature: {}", b58::encode(&signature.0));
    print!("");

    agg_pubkey
        .verify_signature::<Sha256Normalized, _, _>(signature, hash)
        .map_err(|e| anyhow::anyhow!("Invalid signature: {:?}", e))?;
    Ok(())
}
pub fn verify_signature_at_specific_point(
    signature: &[u8; 32],
    hash: &[u8; 64],
    aggregated_pubkey: &[u8; 64],
) -> Result<(), anyhow::Error> {
    let mut input = [0u8; 384];
    let agg_pubkey = G2Point::try_from(G2CompressedPoint(*aggregated_pubkey))
        .map_err(|e| anyhow::anyhow!("Failed to convert to G2Point: {:?}", e))?;
    let signature = G1CompressedPoint(*signature);

    // 1) Hash message to curve
    input[..64].clone_from_slice(hash);
    // 2) Decompress our public key
    input[64..192].clone_from_slice(&agg_pubkey.0);
    // 3) Decompress our signature
    input[192..256].clone_from_slice(&signature.to_bytes().unwrap());

    // 4) Pair with -G2::one()
    input[256..].clone_from_slice(&G2_MINUS_ONE);

    // Calculate result
    if let Ok(r) = alt_bn128_pairing(&input) {
        if r.eq(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ]) {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Invalid signature"))
        }
    } else {
        Err(anyhow::anyhow!("Invalid signature"))
    }
}

pub fn expand_signature(signature: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    let g1_compressed = G1CompressedPoint(*signature);
    let signature_g1 = G1Point::try_from(&g1_compressed)
        .map_err(|e| anyhow::anyhow!("Failed to convert to G1Point: {:?}", e))?;

    Ok(signature_g1.0.to_vec())
}

pub fn get_hash_to_curve_bytes(message: &[u8; 32]) -> Result<([u8; 64], u8), anyhow::Error> {
    for n in 0u8..255 {
        // Create a hash
        let hash = solana_nostd_sha256::hashv(&[message.as_ref(), &[n]]);

        // Convert hash to a Ubig for Bigint operations
        let hash_ubig = UBig::from_be_bytes(&hash);

        // Check if the hash is higher than our normalization modulus of Fq * 5
        if hash_ubig >= NORMALIZE_MODULUS {
            continue;
        }

        let modulus_ubig = hash_ubig % &MODULUS;

        // Decompress the point
        match alt_bn128_g1_decompress(&modulus_ubig.to_be_bytes()) {
            Ok(p) => return Ok((p, n)),
            Err(e) => {
                println!("Error decompressing point: {:?}", e);
                continue;
            }
        };
    }
    Err(anyhow::anyhow!("No valid point found"))
    // // We assume that Sha256Normalized implements HashToCurve and has a try_hash_to_curve function that returns a point with a to_bytes() method.
    // let hash_to_curve = Sha256Normalized::try_hash_to_curve(message)
    //     .map_err(|e| anyhow::anyhow!("Failed to hash to curve: {:?}", e))?;
    // let bytes = hash_to_curve
    //     .to_bytes()
    //     .map_err(|e| anyhow::anyhow!("Failed to convert to bytes: {:?}", e))?;
    // Ok(bytes)
}

pub fn get_hash_to_curve_at_specific_point(
    message: &[u8; 32],
    n: u8,
) -> Result<([u8; 64], u8), anyhow::Error> {
    // Create a hash
    let hash = solana_nostd_sha256::hashv(&[message.as_ref(), &[n]]);

    // Convert hash to a Ubig for Bigint operations
    let hash_ubig = UBig::from_be_bytes(&hash);

    // Check if the hash is higher than our normalization modulus of Fq * 5
    if hash_ubig >= NORMALIZE_MODULUS {
        return Err(anyhow::anyhow!("Hash is higher than normalization modulus"));
    }

    let modulus_ubig = hash_ubig % &MODULUS;

    // Pad to 32 bytes for alt_bn128_g1_decompress
    let modulus_bytes = modulus_ubig.to_be_bytes();
    let mut padded_bytes = [0u8; 32];
    let start = 32usize.saturating_sub(modulus_bytes.len());
    padded_bytes[start..].copy_from_slice(&modulus_bytes);

    // Decompress the point
    match alt_bn128_g1_decompress(&padded_bytes) {
        Ok(p) => return Ok((p, n)),
        Err(e) => {
            println!("Error decompressing point: {:?}", e);
            return Err(anyhow::anyhow!("Error decompressing point: {:?}", e));
        }
    };
}

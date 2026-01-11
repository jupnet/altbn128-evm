use dashu_int::UBig;
use num_traits::ops::checked::CheckedAdd;
use rand::{RngCore, rngs::OsRng};
use solana_alt_bn128_bls::{
    G1CompressedPoint, G2CompressedPoint, G2Point, MODULUS, PrivKey, Sha256Normalized,
};
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
    let mut g2_point = G2Point::try_from(G2CompressedPoint(*aggregated_pubkey))
        .map_err(|e| anyhow::anyhow!("Failed to convert to G2Point: {:?}", e))?;

    // Return both the original BlsPubkey and the expanded G2Point bytes
    Ok(g2_point.0.to_vec())
}

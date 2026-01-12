use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ff::{One, PrimeField, Zero};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AltBn128Error {
    #[error("Hash to curve error: {reason}")]
    HashToCurve { reason: String },
    #[error("Invalid x coordinate")]
    InvalidX,
    #[error("Invalid pubkey length")]
    InvalidPubkeyLength,
    #[error("Invalid signature length")]
    InvalidSignatureLength,
    #[error("Modular exponentiation failed")]
    ModExpFailed,
}

pub struct AltBn128 {
    // Prime field modulus for alt_bn128
    p: BigUint,
    // Normalization modulus for hash-to-curve
    normalize_modulus: BigUint,
    // Negative G2 point for pairing verification
    neg_g2: Vec<u8>,
    // Expected pairing result
    pairing_check: [u8; 32],
}

impl AltBn128 {
    pub fn new() -> Self {
        let p = BigUint::from_str(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        )
        .unwrap();

        let normalize_modulus = BigUint::from_str(
            "109441214359196376111232028726286375443481555786489118313445189473226131042915",
        )
        .unwrap();

        let neg_g2 = hex::decode(concat!(
            "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
            "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
            "275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec",
            "1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d"
        ))
        .unwrap();

        let pairing_check = [0u8; 31]
            .iter()
            .chain([1u8].iter())
            .copied()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        Self {
            p,
            normalize_modulus,
            neg_g2,
            pairing_check,
        }
    }

    /// Decompresses a point on the alt_bn128 curve
    pub fn decompress(&self, x: &BigUint) -> Result<(BigUint, BigUint, bool), AltBn128Error> {
        if x >= &self.p {
            return Err(AltBn128Error::InvalidX);
        }

        // Calculate x^3 + 3 (curve equation y^2 = x^3 + 3)
        let x_squared = (x * x) % &self.p;
        let x_cubed = (&x_squared * x) % &self.p;
        let y_squared = (&x_cubed + 3u32) % &self.p;

        // Check if y^2 is a quadratic residue using Legendre symbol
        let legendre_exp = (&self.p - 1u32) >> 1;
        let legendre = self.mod_exp(&y_squared, &legendre_exp)?;

        if legendre != BigUint::from(1u32) {
            return Ok((BigUint::from(0u32), BigUint::from(0u32), false));
        }

        // Calculate square root using Tonelli-Shanks (for this specific prime, we can use simpler method)
        let sqrt_exp = (&self.p + 1u32) >> 2;
        let mut y = self.mod_exp(&y_squared, &sqrt_exp)?;

        // Choose the smaller root (lexicographically smaller)
        let p_half = &self.p >> 1;
        if y > p_half {
            y = &self.p - y;
        }

        Ok((x.clone(), y, true))
    }

    /// Modular exponentiation using the built-in BigUint method
    pub fn mod_exp(&self, base: &BigUint, exp: &BigUint) -> Result<BigUint, AltBn128Error> {
        Ok(base.modpow(exp, &self.p))
    }

    /// Hash-to-curve mapping using try-and-increment method
    pub fn hash_to_curve(&self, message: &[u8; 32]) -> Result<(BigUint, BigUint), AltBn128Error> {
        for n in 0u8..255 {
            let mut hasher = Sha256::new();
            hasher.update(message);
            hasher.update([n]);
            let hash_result = hasher.finalize();

            let hash_val = BigUint::from_bytes_be(&hash_result);

            if hash_val >= self.normalize_modulus {
                continue;
            }

            let x = hash_val % &self.p;
            println!("x in hash_to_curve: {}", b58::encode(&x.to_bytes_be()));

            if x.to_bytes_be().len() != 32 {
                continue;
            }
            let (found_x, found_y, success) = self.decompress(&x)?;

            if success {
                return Ok((found_x, found_y));
            }
        }

        Err(AltBn128Error::HashToCurve {
            reason: "No valid point found".to_string(),
        })
    }

    pub fn hash_to_curve_first_point(
        &self,
        message: &[u8; 32],
    ) -> Result<(BigUint, BigUint, u8), AltBn128Error> {
        for n in 0u8..255 {
            let mut hasher = Sha256::new();
            hasher.update(message);
            hasher.update([n]);
            let hash_result = hasher.finalize();

            let hash_val = BigUint::from_bytes_be(&hash_result);

            if hash_val >= self.normalize_modulus {
                continue;
            }

            let x = hash_val % &self.p;
            let (found_x, found_y, success) = self.decompress(&x)?;

            if success {
                return Ok((found_x, found_y, n));
            }
        }

        Err(AltBn128Error::HashToCurve {
            reason: "No valid point found".to_string(),
        })
    }

    pub fn hash_to_curve_all_points(
        &self,
        message: &[u8; 32],
    ) -> Result<Vec<(BigUint, BigUint, u8)>, AltBn128Error> {
        let mut points = Vec::new();
        for n in 0u8..255 {
            let mut hasher = Sha256::new();
            hasher.update(message);
            hasher.update([n]);
            let hash_result = hasher.finalize();

            let hash_val = BigUint::from_bytes_be(&hash_result);

            if hash_val >= self.normalize_modulus {
                continue;
            }

            let x = hash_val % &self.p;
            let (found_x, found_y, success) = self.decompress(&x)?;

            if success {
                points.push((found_x, found_y, n));
            }
        }

        Ok(points)
    }

    /// Verify BLS signature using pairing
    pub fn verify_signature(
        &self,
        hash: &[u8; 32],
        pubkey: &[u8],
        signature: &[u8],
    ) -> Result<bool, AltBn128Error> {
        if pubkey.len() != 128 {
            return Err(AltBn128Error::InvalidPubkeyLength);
        }
        if signature.len() != 64 {
            return Err(AltBn128Error::InvalidSignatureLength);
        }

        let (x, y) = self.hash_to_curve(hash)?;

        // Convert coordinates to 32-byte big-endian format
        let x_bytes = self.biguint_to_32_bytes(&x);
        let y_bytes = self.biguint_to_32_bytes(&y);
        println!("x bytes: {}", b58::encode(&x_bytes));
        println!("y bytes: {}", b58::encode(&y_bytes));
        // Prepare input for pairing precompile
        let mut input = Vec::new();
        input.extend_from_slice(&x_bytes);
        input.extend_from_slice(&y_bytes);
        println!("pubkey: {}", b58::encode(pubkey));
        input.extend_from_slice(pubkey);
        println!("signature: {}", b58::encode(signature));
        input.extend_from_slice(signature);
        println!("neg_g2: {}", b58::encode(&self.neg_g2));
        input.extend_from_slice(&self.neg_g2);
        println!("input: {}", b58::encode(&input));

        // In a real implementation, this would call the pairing precompile
        // For now, we'll simulate the pairing check
        let result = self.simulate_pairing_check(&input);

        Ok(result)
    }

    /// Convert BigUint to 32-byte big-endian representation
    fn biguint_to_32_bytes(&self, value: &BigUint) -> [u8; 32] {
        let bytes = value.to_bytes_be();
        let mut result = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        result[start..].copy_from_slice(&bytes);
        result
    }

    /// Real BN254 pairing check - matches EVM behavior exactly
    fn simulate_pairing_check(&self, input: &[u8]) -> bool {
        // Parse the pairing input (same format as EVM precompile)
        // Input format: [G1_x, G1_y, G2_x0, G2_x1, G2_y0, G2_y1, G1_sig_x, G1_sig_y, NEG_G2_x0, NEG_G2_x1, NEG_G2_y0, NEG_G2_y1]
        // Each field element is 32 bytes

        if input.len() != 384 {
            // 12 * 32 bytes = 384 bytes total
            return false;
        }

        // Parse G1 point (hash-to-curve result)
        let g1_x_bytes = &input[0..32];
        let g1_y_bytes = &input[32..64];

        // Parse G2 pubkey (4 field elements: x0, x1, y0, y1)
        let g2_x0_bytes = &input[64..96];
        let g2_x1_bytes = &input[96..128];
        let g2_y0_bytes = &input[128..160];
        let g2_y1_bytes = &input[160..192];

        // Parse G1 signature
        let sig_x_bytes = &input[192..224];
        let sig_y_bytes = &input[224..256];

        // Parse NEG_G2 (4 field elements: x0, x1, y0, y1)
        let neg_g2_x0_bytes = &input[256..288];
        let neg_g2_x1_bytes = &input[288..320];
        let neg_g2_y0_bytes = &input[320..352];
        let neg_g2_y1_bytes = &input[352..384];

        // Convert bytes to field elements
        let g1_x = match Fq::from_be_bytes_mod_order(g1_x_bytes) {
            x if !x.is_zero() || g1_x_bytes.iter().all(|&b| b == 0) => x,
            _ => return false,
        };
        let g1_y = match Fq::from_be_bytes_mod_order(g1_y_bytes) {
            y if !y.is_zero() || g1_y_bytes.iter().all(|&b| b == 0) => y,
            _ => return false,
        };

        let sig_x = match Fq::from_be_bytes_mod_order(sig_x_bytes) {
            x if !x.is_zero() || sig_x_bytes.iter().all(|&b| b == 0) => x,
            _ => return false,
        };
        let sig_y = match Fq::from_be_bytes_mod_order(sig_y_bytes) {
            y if !y.is_zero() || sig_y_bytes.iter().all(|&b| b == 0) => y,
            _ => return false,
        };

        // Convert G2 coordinates
        let g2_x0 = Fq::from_be_bytes_mod_order(g2_x0_bytes);
        let g2_x1 = Fq::from_be_bytes_mod_order(g2_x1_bytes);
        let g2_y0 = Fq::from_be_bytes_mod_order(g2_y0_bytes);
        let g2_y1 = Fq::from_be_bytes_mod_order(g2_y1_bytes);

        let neg_g2_x0 = Fq::from_be_bytes_mod_order(neg_g2_x0_bytes);
        let neg_g2_x1 = Fq::from_be_bytes_mod_order(neg_g2_x1_bytes);
        let neg_g2_y0 = Fq::from_be_bytes_mod_order(neg_g2_y0_bytes);
        let neg_g2_y1 = Fq::from_be_bytes_mod_order(neg_g2_y1_bytes);

        // Construct G1 and G2 points - handle invalid points gracefully
        let g1_point = G1Affine::new_unchecked(g1_x, g1_y);
        if !g1_point.is_on_curve() {
            return false;
        }

        let sig_point = G1Affine::new_unchecked(sig_x, sig_y);
        if !sig_point.is_on_curve() {
            return false;
        }

        // EVM uses (x0, x1) ordering, but arkworks expects (x1, x0) - swap the coordinates
        let g2_x = Fq2::new(g2_x1, g2_x0); // Swapped!
        let g2_y = Fq2::new(g2_y1, g2_y0); // Swapped!
        let g2_point = G2Affine::new_unchecked(g2_x, g2_y);
        if !g2_point.is_on_curve() {
            return false;
        }

        // Same coordinate swapping for NEG_G2
        let neg_g2_x = Fq2::new(neg_g2_x1, neg_g2_x0); // Swapped!
        let neg_g2_y = Fq2::new(neg_g2_y1, neg_g2_y0); // Swapped!
        let neg_g2_point = G2Affine::new_unchecked(neg_g2_x, neg_g2_y);
        if !neg_g2_point.is_on_curve() {
            return false;
        }

        // Perform the pairing check: e(G1, G2) * e(Sig, NEG_G2) == 1
        // This is equivalent to: e(G1, G2) == e(Sig, G2)
        let pairing_result = Bn254::multi_pairing([g1_point, sig_point], [g2_point, neg_g2_point]);

        // Check if the result equals 1 (identity element in the target group)
        pairing_result.0.is_one()
    }
}

impl Default for AltBn128 {
    fn default() -> Self {
        Self::new()
    }
}

impl AltBn128 {
    /// Expose the pairing check for debugging
    pub fn debug_pairing_check(&self, input: &[u8]) -> bool {
        self.simulate_pairing_check(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompress() {
        let altbn128 = AltBn128::new();
        let x = BigUint::from(1u32);
        let result = altbn128.decompress(&x);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash_to_curve() {
        let altbn128 = AltBn128::new();
        let message = [1u8; 32];
        let result = altbn128.hash_to_curve(&message);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_x() {
        let altbn128 = AltBn128::new();
        let x = &altbn128.p + 1u32; // Invalid x (greater than p)
        let result = altbn128.decompress(&x);
        assert!(matches!(result, Err(AltBn128Error::InvalidX)));
    }

    #[test]
    fn test_invalid_pubkey_length() {
        let altbn128 = AltBn128::new();
        let hash = [1u8; 32];
        let pubkey = vec![0u8; 64]; // Wrong length
        let signature = vec![0u8; 64];

        let result = altbn128.verify_signature(&hash, &pubkey, &signature);
        assert!(matches!(result, Err(AltBn128Error::InvalidPubkeyLength)));
    }

    #[test]
    fn test_invalid_signature_length() {
        let altbn128 = AltBn128::new();
        let hash = [1u8; 32];
        let pubkey = vec![0u8; 128];
        let signature = vec![0u8; 32]; // Wrong length

        let result = altbn128.verify_signature(&hash, &pubkey, &signature);
        assert!(matches!(result, Err(AltBn128Error::InvalidSignatureLength)));
    }
}

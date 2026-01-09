# Minimal Alt-BN128 EVM

A Solidity implementation of Alt-BN128 elliptic curve operations for signature verification on Ethereum.

## Overview

This project provides a minimal implementation of Alt-BN128 (also known as BN254) elliptic curve cryptography for the Ethereum Virtual Machine. It includes functionality for:

- Point decompression on the Alt-BN128 curve
- Hash-to-curve mapping
- Signature verification using bilinear pairing

## Installation

```bash
bun install
```

## Usage

### Compile Contracts

```bash
bun run compile
```

### Run Tests

```bash
bun test
```

### Deploy

```bash
bun run deploy
```

## Contract Details

### AltBn128.sol

The main contract implementing Alt-BN128 curve operations:

- `decompress(uint x)`: Decompresses an x-coordinate to a full point (x, y) on the curve
- `hashToCurve(bytes32 message)`: Maps a hash to a valid curve point
- `verifySignature(bytes32 hash, bytes pubkey, bytes signature)`: Verifies an Alt-BN128 signature using bilinear pairing

## Requirements

- Bun >= 1.0.0
- Solidity ^0.8.21

## License

UNLICENSED


## Issues

Either the verification is wrong or the expansion is wrong

```rs
/// Aggregates multiple EVM BLS pubkeys
/// For EVM, we need to aggregate the pubkeys normally first, then adjust the format
pub fn aggregate_evm_pubkeys(pubkeys: &[String]) -> anyhow::Result<(BlsPubkey, Vec<u8>)> {
    // First decode and aggregate pubkeys normally
    let bls_pubkeys: Vec<BlsPubkey> = pubkeys
        .iter()
        .map(|pk| decode_bls_pubkey(pk))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Aggregate using normal BLS aggregation
    let aggregated_pubkey = aggregate_pubkeys(&bls_pubkeys)?;

    // For EVM, we need to convert to G2Point and back, but preserve the first 64 bytes
    let mut g2_point = G2Point::try_from(G2CompressedPoint(aggregated_pubkey.to_bytes()))
        .map_err(|e| anyhow::anyhow!("Failed to convert to G2Point: {:?}", e))?;

    // Overwrite the first 64 bytes with the original aggregated pubkey bytes
    g2_point.0[..64].copy_from_slice(aggregated_pubkey.as_ref());

    // Return both the original BlsPubkey and the expanded G2Point bytes
    Ok((aggregated_pubkey, g2_point.0.to_vec()))
}

```rs
/// Expands a BLS signature for EVM (from 32 bytes compressed to 64 bytes uncompressed G1 point)
pub fn expand_evm_signature(signature: &BlsSignature) -> anyhow::Result<Vec<u8>> {
    let g1_point = G1Point::try_from(&G1CompressedPoint(signature.0))
        .map_err(|e| anyhow::anyhow!("Failed to convert to G1Point: {:?}", e))?;

    Ok(g1_point.0.to_vec())
}
```


```
Fail (but should pass):
Aggregated Pubkey: 65HTQ9s2GdhSMyeb7ANmY6r3wLZTVqTBedEoVgKBSzVHnimD5Py55BtHFm1R6NkzUKWUm2MaB97oRhvy6D8WQqH
Aggregated Singature: CpBiAQGdCt9can81yaquduDDCmV5EQEQfHvi3oy5Xgxd
Hash: 2rDqbvCW1kq8XTJKNPtPvrdqxmMAxuQD4GBRdRADjZnL (0x1b77a999f2ee6dfdec2c36b00605f62717d8f2cd2df9b8907f885f89a4c8d8b5)

Pass:
Aggregated Pubkey: 65HTQ9s2GdhSMyeb7ANmY6r3wLZTVqTBedEoVgKBSzVHnimD5Py55BtHFm1R6NkzUKWUm2MaB97oRhvy6D8WQqH
Aggregated Singature: 9rEJqrPQ3eVxyQWBFWHiAdTx1hJ7FZ1FyMvJgWyTQC9G
Hash: 7gcHBDmGcA3WGfNNBYRVxS8vGAAAv1yB9NsGvAdhpBux (0x634ba9c05eed0b2cfc51c1b30b4320e4fdc8a5d3958a959317e576d811dbcd7f)
```
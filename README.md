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
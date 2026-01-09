// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

contract AltBn128 {
    uint private constant P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    uint private constant NORMALIZE_MODULUS =
        109441214359196376111232028726286375443481555786489118313445189473226131042915;

    bytes private constant NEG_G2 =
        hex"198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
        hex"1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
        hex"275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec"
        hex"1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d";

    bytes32 private constant PAIRING_CHECK = bytes32(uint(1));

    error HashToCurveError(string reason);

    function decompress(uint x_) public view returns (uint, uint, bool) {
        require(x_ < P, "Invalid x");

        uint x3 = mulmod(mulmod(x_, x_, P), x_, P);
        uint y2 = addmod(x3, 3, P);

        uint legendre = modExp(y2, (P - 1) >> 1);
        if (legendre != 1) {
            return (0, 0, false);
        }

        uint y = modExp(y2, (P + 1) >> 2);

        if (y > (P >> 1)) {
            y = P - y;
        }
        return (x_, y, true);
    }

    function modExp(uint base_, uint exp_) public view returns (uint result) {
        assembly {
            let ptr := mload(0x40)

            mstore(ptr, 32)
            mstore(add(ptr, 32), 32)
            mstore(add(ptr, 64), 32)

            mstore(add(ptr, 96), base_)
            mstore(add(ptr, 128), exp_)
            mstore(add(ptr, 160), P)

            let success := staticcall(gas(), 0x05, ptr, 192, ptr, 32)
            if iszero(success) {
                revert(0, 0)
            }
            result := mload(ptr)
        }
    }

    function hashToCurve(bytes32 message_) public view returns (uint x, uint y) {
        for (uint8 n = 0; n < 255; n++) {
            uint hashVal = uint(sha256(abi.encodePacked(message_, n)));

            if (hashVal >= NORMALIZE_MODULUS) {
                continue;
            }
            (uint foundX, uint foundY, bool success) = decompress(hashVal % P);

            if (success) {
                return (foundX, foundY);
            }
        }
        revert HashToCurveError("No valid point found");
    }

    function verifySignature(
        bytes32 hash_,
        bytes memory pubkey_,
        bytes memory signature_
    ) public view returns (bool) {
        require(pubkey_.length == 128, "Invalid pubkey length");
        require(signature_.length == 64, "Invalid signature length");

        (uint x, uint y) = hashToCurve(hash_);

        bytes memory input = abi.encodePacked(
            x,
            y,
            pubkey_,
            signature_,
            NEG_G2
        );

        (bool success, bytes memory result) = address(0x08).staticcall(input);
        return success && bytes32(result) == PAIRING_CHECK;
    }
}
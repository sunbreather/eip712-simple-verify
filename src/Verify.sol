// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "@openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

contract Verify is EIP712 {
    bytes32 constant SIGNED_OBJECT_TYPEHASH =
        keccak256("SignedObject(uint256 value)");

    struct SignedObject {
        uint256 value;
    }

    constructor() EIP712("Verify", "1") {}

    function verify(
        SignedObject calldata signedObject,
        address _signer,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external view {
        address signer = ECDSA.recover(
            _hashTypedDataV4(
                keccak256(
                    abi.encode(SIGNED_OBJECT_TYPEHASH, signedObject.value)
                )
            ),
            v,
            r,
            s
        );
        require(signer == _signer, "Invalid signature");
    }
}

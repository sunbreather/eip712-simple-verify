// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Verify {
    bytes32 public immutable EIP712_DOMAIN_TYPE;
    bytes32 public constant APP_NAME = keccak256(bytes("Verify"));
    bytes32 public constant VERSION = keccak256(bytes("1"));
    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    bytes32 public constant SIG_VOTE_TYPEHASH =
        keccak256("SignedObject(uint256 Id,address sender)");

    struct SignedObject {
        uint256 Id;
        address sender;
    }

    constructor() {
        EIP712_DOMAIN_TYPE = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                APP_NAME,
                VERSION,
                block.chainid,
                address(this)
            )
        );
    }

    function verify(
        SignedObject calldata signedObject,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 hash_ = keccak256(
            abi.encodePacked(
                "\x19\x01",
                EIP712_DOMAIN_TYPE,
                keccak256(
                    abi.encode(
                        SIG_VOTE_TYPEHASH,
                        signedObject.Id,
                        signedObject.sender
                    )
                )
            )
        );
        address _signer = ecrecover(hash_, v, r, s);
        require(signedObject.sender == _signer, "Invalid signature");
    }
}

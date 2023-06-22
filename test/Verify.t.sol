// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Verify.sol";
import "@openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract VerifyTest is Test {
    Verify verify;

    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    bytes32 constant SIGNED_OBJECT_TYPEHASH =
        keccak256("SignedObject(uint256 value)");
    bytes32 constant APP_NAME = keccak256(bytes("Verify"));
    bytes32 constant VERSION = keccak256(bytes("1"));

    function setUp() public {
        verify = new Verify();
    }

    function testVerify() public {
        bytes32 EIP712_DOMAIN_TYPE = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                APP_NAME,
                VERSION,
                block.chainid,
                address(verify)
            )
        );

        bytes32 hash_ = ECDSA.toTypedDataHash(
            EIP712_DOMAIN_TYPE,
            keccak256(abi.encode(SIGNED_OBJECT_TYPEHASH, 1))
        );

        Verify.SignedObject memory so = Verify.SignedObject(1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, hash_);
        verify.verify(so, vm.addr(1), v, r, s);
    }
}

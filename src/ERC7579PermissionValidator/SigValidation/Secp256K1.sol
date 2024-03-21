// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { ISigValidationAlgorithm } from "./ISigValidationAlgorithm.sol";

import "forge-std/Console2.sol";

contract Secp256K1SigValidationAlgorithm is ISigValidationAlgorithm {
    using MessageHashUtils for bytes32;
    using ECDSA for bytes32;

    function validateSignature(
        bytes32 dataHash,
        bytes memory signature,
        bytes calldata signer
    )
        public
        pure
        returns (bool)
    {
        require(signature.length == 65, "Invalid signature length");

        //address recovered = (dataHash.toEthSignedMessageHash()).recover(signature);
        address recovered = dataHash.recover(signature);
        
        console2.log("256K1 algo: recovered: ", recovered);
        console2.log("256K1 algo: signer: ", address(bytes20(signer[0:20])));

        if (address(bytes20(signer[0:20])) != recovered) {
            revert("k1 sig validator: Invalid signature");
        }
        // omit for now
        /*
        recovered = dataHash.recover(signature);
        if (address(bytes20(signer[0:20])) == recovered) {
            return true;
        }
        return false;
        */
    }
}

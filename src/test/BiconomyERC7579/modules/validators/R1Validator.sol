// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";
import { ECDSA } from "solady/src/utils/ECDSA.sol";
import { MODULE_TYPE_VALIDATOR, VALIDATION_SUCCESS, VALIDATION_FAILED } from "../../interfaces/modules/IERC7579Modules.sol";
import { IValidator } from "../../interfaces/modules/IValidator.sol";
import { ERC1271_MAGICVALUE, ERC1271_INVALID } from "../../types/Constants.sol";
import { EncodedModuleTypes } from "../../lib/ModuleTypeLib.sol";

import "forge-std/Console2.sol";

contract R1Validator is IValidator {

    event RecoveredAddressVsSigner(address recovered, address signer);
    event K1SigValidatorInvalidSignature();
    event UserOpHash(bytes32 userOpHash);

    using SignatureCheckerLib for address;

    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    mapping(address sa => address owner) public smartAccountOwners;

    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG
    //////////////////////////////////////////////////////////////////////////*/

    // TODO // Review comments
    function onInstall(bytes calldata data) external override {
        if (data.length == 0) return;
        address owner = address(bytes20(data)); // encodePacked
        // OR // abi.decode(data, (address));
        smartAccountOwners[msg.sender] = owner;
    }

    function onUninstall(bytes calldata) external override {
        delete smartAccountOwners[msg.sender];
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return smartAccountOwners[smartAccount] != address(0);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external view override returns (uint256) {

        address owner = smartAccountOwners[userOp.sender];
        bool validSig = owner.isValidSignatureNow(
            ECDSA.toEthSignedMessageHash(userOpHash),
            userOp.signature
        );
        /* emit UserOpHash(ECDSA.toEthSignedMessageHash(userOpHash));
        emit RecoveredAddressVsSigner(
            ECDSA.recover(ECDSA.toEthSignedMessageHash(userOpHash), userOp.signature),
            owner
        ); */
        if (!validSig) {
            validSig = owner.isValidSignatureNow(
                userOpHash,
                userOp.signature
            ); 
        }
        /* emit UserOpHash(userOpHash);
        emit RecoveredAddressVsSigner(
            ECDSA.recover(userOpHash, userOp.signature),
            owner
        ); */
        if (!validSig) {
            return VALIDATION_FAILED;
            //emit K1SigValidatorInvalidSignature();
        }
        return VALIDATION_SUCCESS;
    }

    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    ) external view override returns (bytes4) {
        address owner = smartAccountOwners[sender];
        // use the simple 1271 replay protection
        hash = keccak256(
                    abi.encodePacked(
                        "\x19Ethereum Signed Message:\n52",
                        hash,
                        sender
                    )
                );
        return
            SignatureCheckerLib.isValidSignatureNowCalldata(owner, hash, data) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    function getModuleTypes() external view override returns (EncodedModuleTypes) {}

    function name() external pure returns (string memory) {
        return "R1Validator";
    }

    function version() external pure returns (string memory) {
        return "0.0.1";
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR;
    }
}

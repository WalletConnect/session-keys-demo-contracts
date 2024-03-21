// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    IModule,
    IValidator,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "erc7579/interfaces/IERC7579Module.sol";
import { EncodedModuleTypes } from "../modulekit/ModuleTypeLib.sol";
import { ISigValidationAlgorithm } from "./SigValidation/ISigValidationAlgorithm.sol";
import {
    I1271SignatureValidator, EIP1271_MAGIC_VALUE
} from "../interfaces/I1271SignatureValidator.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { _packValidationData } from "account-abstraction/core/Helpers.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

type ValidAfter is uint48;

type ValidUntil is uint48;

struct SingleSignerPermission {
    ValidUntil validUntil;
    ValidAfter validAfter;
    address signatureValidationAlgorithm;
    bytes signer;
    // TODO: change it to address[] and bytes[] to be able to
    // stack policies for a permission
    // as of now it is enough to have a single policy for demo purposes
    address policy;
    bytes policyData;
}

/*
  TODO: nonces
  TODO: renounce permissions (including that is not enabled yet)
*/

/**
 * Modular Permission Validator 
 * Heavily inspired by Biconomy Session Key Manager v2 by ankur<at>biconomy.io
 * Ported to ERC-7579 and updated by filipp.makarov<at>biconomy.io
 */

contract ERC7579PermissionValidator is IValidator {
    
    using MessageHashUtils for bytes32;

    mapping(
        bytes32 singleSignerPermissionId => mapping(address smartAccount => SingleSignerPermission)
    ) public enabledPermissions;

    /// @inheritdoc IValidator
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        returns (uint256 validationData)
    {
        if (_isBatchExecuteCall(userOp)) {
            // TODO: Add batched execution later, use just single for demo purposes
            //validationData = _validateUserOpBatchExecute(userOp, userOpHash);
            revert("Permissions: Batch Execution SOON (tm)");
        } else {
            validationData = _validateUserOpSingleExecute(userOp, userOpHash);
        }
    }

    function checkPermissionForSmartAccount(
        address smartAccount,
        bytes calldata permissionDataFromContext
    )
        external
        view
        returns (bytes32 permissionPrefix)
    {
        (
            /*uint256 permissionIndex*/
            ,
            ValidUntil validUntil,
            ValidAfter validAfter,
            address signatureValidationAlgorithm,
            bytes memory signer,
            address policy,
            bytes memory policyData,
            /*bytes memory permissionEnableData*/
            ,
            /*bytes memory permissionEnableSignature*/
        ) = abi.decode(
            permissionDataFromContext,
            (uint256, ValidUntil, ValidAfter, address, bytes, address, bytes, bytes, bytes)
        );

        bytes32 permissionId = _getPermissionDataDigestFromUnpacked(
            validUntil, validAfter, signatureValidationAlgorithm, signer, policy, policyData
        );

        if (!_isPermissionEnabledForSmartAccount(permissionId, smartAccount)) {
            return keccak256("Permission Not Enabled");
        } else {
            return permissionId;
        }
    }

    /**
     * Single Call Handler **********************************
     */
    function _validateUserOpSingleExecute(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        internal
        returns (uint256 rv)
    {
        /*
         * Module Signature Layout
         * Offset (in bytes)    | Length (in bytes) | Contents
        * 0x0                  | 0x1               | 0x01 if sessionEnableTransaction, 0x00
        otherwise
         * 0x1                  | --                | Data depending on the above flag
         */

        if (_isSessionEnableTransaction(userOp.signature)) {
            (
                uint256 permissionIndex,
                ValidUntil validUntil,
                ValidAfter validAfter,
                address signatureValidationAlgorithm,
                bytes memory signer,
                address policy,
                bytes memory policyData,
                bytes memory permissionEnableData,
                bytes memory permissionEnableSignature,
                bytes memory signerSignature
            ) =
            //TODO: re-write this with assembly
            abi.decode(
                userOp.signature,
                (
                    uint256,
                    ValidUntil,
                    ValidAfter,
                    address,
                    bytes,
                    address,
                    bytes,
                    bytes,
                    bytes,
                    bytes
                )
            );

            _verifyPermissionEnableDataSignature(
                permissionEnableData,
                permissionEnableSignature, // it should contain data of the existing permission that
                    // signed the enabling of the new permission
                userOp.sender
            );

            _validatePermissionEnableTransactionAndEnablePermission(
                validUntil,
                validAfter,
                permissionIndex,
                signatureValidationAlgorithm,
                signer,
                policy,
                policyData,
                permissionEnableData
            );

            // at this point permission is enabled

            // now let's use it

            // 1. TODO: iterate over Policies to see if none of them are violated
            // revert if they have been violated

            // pretend permissions are not violated :)
            bool arePermissionsViolated = false;

            // check that it was actually signed by a proper signer (session key)
            ISigValidationAlgorithm(signatureValidationAlgorithm).validateSignature(
                userOpHash, signerSignature, signer
            );

            rv = _packValidationData(
                //_packValidationData expects true if sig validation has failed, false otherwise
                arePermissionsViolated,
                ValidUntil.unwrap(validUntil),
                ValidAfter.unwrap(validAfter)
            );
        } else {
            /*
            (
                bytes32 permissionDataDigest_,
                bytes calldata signerSignature
            ) = _parsePermissionDataPreEnabledSignatureSingleCall(userOp.signature);
            */
            // just doing it with abi.decode for consistency
            (bytes32 permissionDataDigest_, bytes memory signerSignature) =
                abi.decode(userOp.signature, (bytes32, bytes));

            SingleSignerPermission storage permission =
                _validatePermissionPreEnabled(userOp.sender, permissionDataDigest_);

            // 1. TODO: iterate over Policies to see if none of them are violated
            bool arePermissionsViolated = false;

            //check that it was actually signed by a proper signer (session key)
            ISigValidationAlgorithm(permission.signatureValidationAlgorithm).validateSignature(
                userOpHash, signerSignature, permission.signer
            );

            rv = _packValidationData(
                //_packValidationData expects true if sig validation has failed, false otherwise
                arePermissionsViolated,
                ValidUntil.unwrap(permission.validUntil),
                ValidAfter.unwrap(permission.validAfter)
            );
        }
    }

    function _isSessionEnableTransaction(bytes calldata _moduleSignature)
        internal
        pure
        returns (bool isSessionEnableTransaction)
    {
        assembly ("memory-safe") {
            isSessionEnableTransaction :=
                shr(
                    248, // TODO: CHECK THIS, REPLACE WITH CONSTANT
                    calldataload(_moduleSignature.offset)
                )
        }
    }

    function _verifyPermissionEnableDataSignature(
        bytes memory _sessionEnableData,
        bytes memory _sessionEnableSignature,
        address _smartAccount
    )
        internal
        view
    {
        // Verify the signature on the session enable data
        // 1. get the _sessionEnableData digest that was signed
        // 2. forward it to the SA.isValidSignature interface
        //    obviously we expect the SA _sessionEnableSignature to contain the info for SA to
        // forward to the right module
        // revert if something is wrong

        // Pretend everything is signed properly atm

        // Uncomment when SA is ready to it

        if (
            I1271SignatureValidator(_smartAccount).isValidSignature(
                keccak256(_sessionEnableData).toEthSignedMessageHash(), _sessionEnableSignature
            ) != EIP1271_MAGIC_VALUE
        ) {
            revert("Permissions: PermissionEnableSignatureInvalid");
        }
    }

    function _validatePermissionEnableTransactionAndEnablePermission(
        ValidUntil validUntil,
        ValidAfter validAfter,
        uint256 permissionIndex,
        address signatureValidationAlgorithm,
        bytes memory signer,
        address policy,
        bytes memory policyData,
        bytes memory permissionEnableData
    )
        internal
    {
        (uint64 permissionChainId, bytes32 permissionDigest) =
            this._parsePermissionFromPermissionEnableData(permissionEnableData, permissionIndex);

        if (permissionChainId != block.chainid) {
            revert("Permissions: ChainIdMismatch");
        }

        bytes32 computedDigest = _getPermissionDataDigestFromUnpacked(
            validUntil, validAfter, signatureValidationAlgorithm, signer, policy, policyData
        );

        if (permissionDigest != computedDigest) {
            revert("Permissions: PermissionDigestMismatch");
        }

        // Cache the session key data in the smart account storage for next validation
        SingleSignerPermission memory permission = SingleSignerPermission({
            validUntil: validUntil,
            validAfter: validAfter,
            signatureValidationAlgorithm: signatureValidationAlgorithm,
            signer: signer,
            policy: policy,
            policyData: policyData
        });
        enabledPermissions[computedDigest][msg.sender] = permission;
        //TODO Emit event
    }

    function _isPermissionEnabledForSmartAccount(
        bytes32 permissionId,
        address smartAccount
    )
        internal
        view
        returns (bool)
    {
        return enabledPermissions[permissionId][smartAccount].signatureValidationAlgorithm
            != address(0) || enabledPermissions[permissionId][smartAccount].policy != address(0);
    }

    function _validatePermissionPreEnabled(
        address smartAccount,
        bytes32 permissionId
    )
        internal
        view
        returns (SingleSignerPermission storage permission)
    {
        require(
            _isPermissionEnabledForSmartAccount(permissionId, smartAccount),
            "Permissions: Permission is not enabled"
        );
        permission = enabledPermissions[permissionId][smartAccount];
    }

    function _parsePermissionFromPermissionEnableData(
        bytes calldata _permissionEnableData,
        uint256 _permissionIndex
    )
        // TODO: change public to internal when initial decoding is done via assembly
        // so we do not need to use this._parsePermissionFromPermissionEnableData
        public
        pure
        returns (uint64 permissionChainId, bytes32 permissionDigest)
    {
        uint8 enabledPermissionsCount;

        /*
         * Session Enable Data Layout
         * Offset (in bytes)    | Length (in bytes) | Contents
         * 0x0                  | 0x1               | No of session keys enabled
         * 0x1                  | 0x8 x count       | Chain IDs
         * 0x1 + 0x8 x count    | 0x20 x count      | Session Data Hash
         */
        assembly ("memory-safe") {
            let offset := _permissionEnableData.offset

            enabledPermissionsCount := shr(248, calldataload(offset))
            offset := add(offset, 0x1)

            permissionChainId := shr(192, calldataload(add(offset, mul(0x8, _permissionIndex))))
            offset := add(offset, mul(0x8, enabledPermissionsCount))

            permissionDigest := calldataload(add(offset, mul(0x20, _permissionIndex)))
        }

        if (_permissionIndex >= enabledPermissionsCount) {
            revert("SKM: SessionKeyIndexInvalid");
        }
    }

    function _parsePermissionDataPreEnabledSignatureSingleCall(bytes calldata _moduleSignature)
        internal
        pure
        returns (bytes32 permissionDataDigest_, bytes calldata signerSignature)
    {
        /*
         * Session Data Pre Enabled Signature Layout
         * Offset (in bytes)    | Length (in bytes) | Contents
         * 0x0                  | 0x1               | Is Session Enable Transaction Flag
        * 0x1                  | --                | abi.encode(bytes32 permissionDataDigest,
        sessionKeySignature)
         */
        assembly ("memory-safe") {
            let offset := add(_moduleSignature.offset, 0x1)
            let baseOffset := offset

            permissionDataDigest_ := calldataload(offset)
            offset := add(offset, 0x20)

            let dataPointer := add(baseOffset, calldataload(offset))
            signerSignature.offset := add(dataPointer, 0x20)
            signerSignature.length := calldataload(dataPointer)
        }
    }

    function _getPermissionDataDigestFromUnpacked(
        ValidUntil validUntil,
        ValidAfter validAfter,
        address signatureValidationAlgorithm,
        bytes memory signer,
        address policy,
        bytes memory policyData
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                validUntil, validAfter, signatureValidationAlgorithm, signer, policy, policyData
            )
        );
    }

    function _isBatchExecuteCall(PackedUserOperation calldata _userOp)
        internal
        pure
        returns (bool isBatchExecuteCall)
    {
        // TODO: verify thru 7579 execution mode
        return false; // for demo purposes just assume it is single exec
    }

    // ==========================
    // ==========================
    // ==========================

    /// @inheritdoc IValidator
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        returns (bytes4)
    {
        sender;
        hash;
        data;
        return 0xffffffff;
    }

    /// @inheritdoc IModule
    function onInstall(bytes calldata data) external {
        //smartAccountOwners[msg.sender] = address(bytes20(data));
    }

    /// @inheritdoc IModule
    function onUninstall(bytes calldata data) external {
        //delete smartAccountOwners[msg.sender];
    }

    /// @inheritdoc IModule
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == 1;
    }

    /// @inheritdoc IModule
    function isInitialized(address) external pure returns (bool) {
        // TODO: how do we know it was initialized?
        return true;
    }

    function getModuleTypes() external view returns (uint256) {
        // solhint-disable-previous-line no-empty-blocks
        //return EncodedModuleTypes.unwrap(somevar);
    }

    // Review
    function test(uint256 a) public {
        a;
    }

    function getSingleSignerPermissionId(
        ValidUntil validUntil,
        ValidAfter validAfter,
        address signatureValidationAlgorithm,
        bytes calldata signer,
        address[] calldata policies,
        bytes[] calldata policyDatas
    )
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                //
            )
        );
    }
}

/**
 * TODO:
 *
 * [ ] add simple ecdsa algorithm contract
 * [ ] add erc721 token policy contract (whatever is required for demo dapp)
 */

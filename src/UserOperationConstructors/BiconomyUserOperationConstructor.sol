// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IUserOpConstructor, PackedUserOperation } from "./IUserOperationConstructor.sol";
import { IPermissionChecker } from "./IPermissionChecker.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { Execution, ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";

/*
 TODO: nonces
 TODO: renounce permissions (including that is not enabled yet)
*/

contract BiconomyUserOpConstructor is IUserOpConstructor {
    /**
     *    PermissionContext is a bytes array with abi.encode:
     *    1. PermissionValidator address (20 bytes)
     *    2. PermissionData as per the Std7579PermissionsModule:
     *         uint256 permissionIndex,
     *         uint48 validUntil,
     *         uint48 validAfter,
     *         address signatureValidationAlgorithm,
     *         bytes memory signer,
     *         address policy,
     *         bytes memory policyData,
     *         bytes memory permissionEnableData,
     *         bytes memory permissionEnableSignature,
     *         bytes memory signerSignature
     */
    IEntryPoint public immutable entryPoint;

    constructor(address _entryPoint) {
        entryPoint = IEntryPoint(_entryPoint);
    }

    function getNonceWithContext(
        address smartAccount,
        bytes calldata permissionsContext
    )
        external
        view
        returns (uint256 nonce)
    {
        address permissionValidator = address(bytes20(permissionsContext[0:20]));
        uint192 key = uint192(bytes24(bytes20(address(permissionValidator))));
        nonce = entryPoint.getNonce(address(smartAccount), key);
    }

    function getCallDataWithContext(
        address, /* smartAccount */
        Execution[] calldata executions,
        bytes calldata /* permissionsContext */
    )
        external
        pure
        returns (bytes memory callDataWithContext)
    {
        if (executions.length == 0) {
            revert("No executions provided");
        }
        if (executions.length == 1) {
            callDataWithContext = abi.encodeCall(
                IERC7579Account.execute,
                (
                    ModeLib.encodeSimpleSingle(),
                    ExecutionLib.encodeSingle(
                        executions[0].target, executions[0].value, executions[0].callData
                        )
                )
            );
        } else {
            callDataWithContext = abi.encodeCall(
                IERC7579Account.execute,
                (ModeLib.encodeSimpleBatch(), ExecutionLib.encodeBatch(executions))
            );
        }
        // TODO: add delegatecall, tryExecute and other execution modes handling
    }

    function getSignatureWithContext(
        address smartAccount,
        PackedUserOperation calldata userOp,
        bytes calldata permissionsContext
    )
        external
        view
        returns (bytes memory signature)
    {
        address permissionValidator = address(bytes20(permissionsContext[0:20]));

        // What if permission has already been set?
        bytes32 result = IPermissionChecker(permissionValidator).checkPermissionForSmartAccount(
            smartAccount, permissionsContext[20:]
        );

        if (result == keccak256("Permission Not Enabled")) {
            // just use the full data required to enable the permission
            signature = abi.encode(permissionsContext[20:], userOp.signature);
        } else {
            // just use the permissionId returned as result
            signature = abi.encode(result, userOp.signature);
        }
    }
}

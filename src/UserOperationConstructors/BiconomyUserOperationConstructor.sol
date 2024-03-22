// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IUserOpConstructor, PackedUserOperation } from "./IUserOperationConstructor.sol";
import { IPermissionChecker } from "./IPermissionChecker.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { Execution, ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { ValidAfter, ValidUntil, SingleSignerPermission } from "src/ERC7579PermissionValidator/IERC7579PermissionValidator.sol";

import "forge-std/Console2.sol";

/*
   TODO: what if at the time of permission creation, even the permission module is
   not yet enabled for the SA?
   */

contract BiconomyUserOpConstructor is IUserOpConstructor {
    /**
     *    PermissionContext is a bytes array with abi.encode:
     *    1. PermissionValidator address (20 bytes)
     *    2. PermissionData as per the Std7579PermissionsModule:
     *         0x01
     *         uint256 permissionIndex,
     *         uint48 validUntil,
     *         uint48 validAfter,
     *         address signatureValidationAlgorithm,
     *         bytes memory signer,
     *         address policy,
     *         bytes memory policyData,
     *         bytes memory permissionEnableData,
     *         bytes memory permissionEnableSignature
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
        returns (bytes memory)
    {
        if (permissionsContext.length <= 20) {
            return userOp.signature;
        }
        
        address permissionValidator = address(bytes20(permissionsContext[0:20]));

        console2.log("permission context w/o validator address: ");
        console2.logBytes(permissionsContext[20:]);

        bytes32 result = IPermissionChecker(permissionValidator).checkPermissionForSmartAccount(
            smartAccount, permissionsContext[20:]
        );

        console2.log("user Op constructor checked permission");

        bytes1 flag = bytes1(permissionsContext[0:1]);

        console2.log("user Op constructor decoding permission context");

        (
                uint256 permissionIndex,
                SingleSignerPermission memory permission,
                bytes memory permissionEnableData,
                bytes memory permissionEnableSignature
            ) =
            abi.decode(
                permissionsContext[21:], //to cut the is enable tx flag
                (
                    uint256,
                    SingleSignerPermission,
                    bytes,
                    bytes
                )
            );
        console2.log("user Op constructor decoded permission context");

        if (result == keccak256("Permission Not Enabled")) {
            // just use the full data required to enable the permission
            return 
                abi.encodePacked(
                    flag,
                    abi.encode(
                        permissionIndex,
                        permission,
                        permissionEnableData,
                        permissionEnableSignature,
                        userOp.signature
                    )
                );
        } else {
            // just use the permissionId returned as result
            return abi.encodePacked(result, userOp.signature);
        }

    }
}


/*
00000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000
*/


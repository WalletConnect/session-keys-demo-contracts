// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IUserOpConstructor, PackedUserOperation } from "./IUserOperationConstructor.sol";
import { IPermissionChecker } from "./IPermissionChecker.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { Execution, ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import "forge-std/console.sol";

struct ValidationConfig {
    uint32 nonce;
    address hook;
}

interface IKernel {
    function rootValidator() external view returns (bytes21);
    function validatorConfig(bytes21 vId) external view returns (ValidationConfig memory);
}

function getValidator(bytes21 validationId) pure returns (address v) {
    assembly {
        v := shr(88, validationId)
    }
}

function encodeAsNonceKey(
    bytes1 mode,
    bytes1 vType,
    bytes20 ValidationIdWithoutType,
    uint16 nonceKey
)
    pure
    returns (uint192 res)
{
    assembly {
        res := or(nonceKey, shr(80, ValidationIdWithoutType))
        res := or(res, shr(72, vType))
        res := or(res, shr(64, mode))
    }
}
/// @notice  THIS IS EXPERIMENTAL AND NOT AUDITED, PLEASE USE IT WITH CARE

contract KernelV3UserOpConstructor is IUserOpConstructor {
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
        bool deployed = smartAccount.code.length > 0;
        bytes1 mode = bytes1(permissionsContext[0]);
        require(mode == bytes1(uint8(1)) || mode == bytes1(0)); // does not support install mode now
        bytes1 vType = bytes1(permissionsContext[1]);
        require(vType == bytes1(uint8(1)) || vType == bytes1(0)); // does not support kernel
        if (mode == bytes1(uint8(1)) && deployed) {
            ValidationConfig memory config =
                IKernel(smartAccount).validatorConfig(bytes21(permissionsContext[1:22]));
            if (config.hook != address(0)) {
                // if validator is already installed, skip enable mode
                mode = bytes1(0);
                // TODO: to make sure the enable mode is not trying to override, check the hook,
                // hook data, selectorData
            }
        }
        bytes21 validationId;
        if (vType == bytes1(uint8(1))) {
            uint192 key = encodeAsNonceKey(mode, vType, bytes20(permissionsContext[2:22]), 0);
            nonce = entryPoint.getNonce(address(smartAccount), key);
            validationId = bytes21(permissionsContext[1:22]);
        } else {
            nonce = entryPoint.getNonce(address(smartAccount), 0);
        }
    }

    function getCallDataWithContext(
        address smartAccount,
        Execution[] calldata executions,
        bytes calldata permissionsContext
    )
        external
        view
        returns (bytes memory callDataWithContext)
    {
        bool deployed = smartAccount.code.length > 0;
        bytes1 mode = bytes1(permissionsContext[0]);
        require(mode == bytes1(uint8(1)) || mode == bytes1(0)); // does not support install mode now
        bytes1 vType = bytes1(permissionsContext[1]);
        require(vType == bytes1(uint8(1)) || vType == bytes1(0)); // does not support kernel
            // permission type now
        bytes21 validationId;
        if (vType == bytes1(uint8(1))) {
            validationId = bytes21(permissionsContext[1:22]);
        } else if (deployed) {
            validationId = IKernel(smartAccount).rootValidator();
        }
        // since kernel v3 use same erc7579 execute, use same calldata
        // NOTE: this will not work with validations that has the hooks, TODO
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
        if (deployed) {
            ValidationConfig memory config = IKernel(smartAccount).validatorConfig(validationId);
            if (config.hook == address(0)) {
                require(
                    mode == bytes1(uint8(1)), "uninstalled validators has to work with enable mode"
                );
            } else if (config.hook == address(1)) {
                return callDataWithContext;
            } else {
                return abi.encodePacked(IERC7579Account.executeUserOp.selector, callDataWithContext);
            }
        } else if (vType == bytes1(uint8(0))) {
            // let's assume root validator does not require hook
            return callDataWithContext;
        } else {
            require(
                mode == bytes1(uint8(1)),
                "using non-root validator with not deployed wallet should be enable mode"
            );
            address hook = address(bytes20(permissionsContext[0:20]));
            if (hook == address(0) || hook == address(1)) {
                return callDataWithContext;
            }
            return abi.encodePacked(IERC7579Account.executeUserOp.selector, callDataWithContext);
        }
    }

    struct MTemp {
        address hook;
        bytes validatorData;
        bytes hookData;
        bytes selectorData;
        bytes enableSig;
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
        bytes1 mode = bytes1(permissionsContext[0]);
        require(mode == bytes1(uint8(1)) || mode == bytes1(0)); // does not support install mode now
        bytes1 vType = bytes1(permissionsContext[1]);
        require(vType == bytes1(uint8(1)) || vType == bytes1(0)); // does not support kernel
            // permission type now
        address permissionValidator;
        if (vType == bytes1(uint8(1))) {
            permissionValidator = address(bytes20(permissionsContext[2:22]));
            permissionsContext = permissionsContext[22:];
        } else {
            permissionsContext = permissionsContext[2:];
        }
        bool deployed = smartAccount.code.length > 0;
        // deal with enableData
        // userOp.signature will be userOpSig
        // enableSig
        // abi.encodePacked(
        //    abi.encodePacked(hook), abi.encode(validatorData, hookData, selectorData, enableSig,
        // userOpSig)
        //);
        if (mode == bytes1(0)) {
            return userOp.signature;
        } else if (deployed) { }
        MTemp memory t;
        t.hook = address(bytes20(permissionsContext[0:20]));
        (t.validatorData, t.hookData, t.selectorData, t.enableSig) =
            abi.decode(permissionsContext[20:], (bytes, bytes, bytes, bytes));
        return abi.encodePacked(
            t.hook,
            abi.encode(t.validatorData, t.hookData, t.selectorData, t.enableSig, userOp.signature)
        );
    }
}

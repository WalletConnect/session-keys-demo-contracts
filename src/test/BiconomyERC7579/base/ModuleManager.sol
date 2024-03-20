// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IModuleManager } from "../interfaces/base/IModuleManager.sol";
import { Storage } from "./Storage.sol";
import { IModule } from "../interfaces/modules/IModule.sol";
import { IValidator } from "../interfaces/modules/IValidator.sol";
import { IExecutor } from "../interfaces/modules/IExecutor.sol";
import { IHook } from "../interfaces/modules/IHook.sol";
import { IFallback } from "../interfaces/modules/IFallback.sol";
import { MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR } from "../interfaces/modules/IERC7579Modules.sol";
import { Receiver } from "solady/src/accounts/Receiver.sol";
import { SentinelListLib } from "sentinellist/SentinelList.sol";

// Note: importing Receiver.sol from solady (but can make custom one for granular control for fallback management)
// Review: This contract could also act as fallback manager rather than having a separate contract
// Review: Kept a different linked list for validators, executors
abstract contract ModuleManager is Storage, Receiver, IModuleManager {
    using SentinelListLib for SentinelListLib.SentinelList;

    modifier withHook() virtual {
        address hook = _getHook();
        if (hook == address(0)) {
            _;
        } else {
            bytes memory hookData = IHook(hook).preCheck(msg.sender, msg.data);
            _;
            if (!IHook(hook).postCheck(hookData)) revert HookPostCheckFailed();
        }
    }

    modifier onlyExecutorModule() virtual {
        SentinelListLib.SentinelList storage executors = _getAccountStorage().executors;
        if (!executors.contains(msg.sender)) revert InvalidModule(msg.sender);
        _;
    }

    modifier onlyValidatorModule(address validator) virtual {
        SentinelListLib.SentinelList storage validators = _getAccountStorage().validators;
        if (!validators.contains(validator)) revert InvalidModule(validator);
        _;
    }

    /**
     * @notice Installs a Module of a certain type on the smart account.
     * @param moduleTypeId The module type ID.
     * @param module The module address.
     * @param initData Initialization data for the module.
     */
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external payable virtual;

    /**
     * @notice Uninstalls a Module of a certain type from the smart account.
     * @param moduleTypeId The module type ID.
     * @param module The module address.
     * @param deInitData De-initialization data for the module.
     */
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData) external payable virtual;

    /**
     * THIS IS NOT PART OF THE STANDARD
     * Helper Function to access linked list
     */
    function getValidatorsPaginated(
        address cursor,
        uint256 size
    ) external view virtual returns (address[] memory array, address next) {
        (array, next) = _getValidatorsPaginated(cursor, size);
    }

    /**
     * THIS IS NOT PART OF THE STANDARD
     * Helper Function to access linked list
     */
    function getExecutorsPaginated(
        address cursor,
        uint256 size
    ) external view virtual returns (address[] memory array, address next) {
        (array, next) = _getExecutorsPaginated(cursor, size);
    }

    /**
     * @notice Checks if a module is installed on the smart account.
     * @param moduleTypeId The module type ID.
     * @param module The module address.
     * @param additionalContext Additional context for checking installation.
     * @return True if the module is installed, false otherwise.
     */
    function isModuleInstalled(
        uint256 moduleTypeId,
        address module,
        bytes calldata additionalContext
    ) external view virtual returns (bool);

    function _initModuleManager() internal virtual {
        // account module storage
        AccountStorage storage ams = _getAccountStorage();
        ams.executors.init();
        ams.validators.init();
    }

    // /////////////////////////////////////////////////////
    // //  Manage Validators
    // ////////////////////////////////////////////////////

    // // TODO
    // // Review this agaisnt required hook/permissions at the time of installations
    function _installValidator(address validator, bytes calldata data) internal virtual {
        // Note: Idea is should be able to check supported interface and module type - eligible validator
        if (!IModule(validator).isModuleType(MODULE_TYPE_VALIDATOR)) revert IncompatibleValidatorModule(validator);

        SentinelListLib.SentinelList storage validators = _getAccountStorage().validators;
        validators.push(validator);
        IValidator(validator).onInstall(data);
    }

    function _uninstallValidator(address validator, bytes calldata data) internal virtual {
        // check if its the last validator. this might brick the account
        (address[] memory array, ) = _getValidatorsPaginated(address(0x1), 10);
        if (array.length == 1) {
            revert CannotRemoveLastValidator();
        }

        SentinelListLib.SentinelList storage validators = _getAccountStorage().validators;

        (address prev, bytes memory disableModuleData) = abi.decode(data, (address, bytes));
        validators.pop(prev, validator);
        IValidator(validator).onUninstall(disableModuleData);
    }

    // /////////////////////////////////////////////////////
    // //  Manage Executors
    // ////////////////////////////////////////////////////

    function _installExecutor(address executor, bytes calldata data) internal virtual {
        // Note: Idea is should be able to check supported interface and module type - eligible validator
        if (!IModule(executor).isModuleType(MODULE_TYPE_EXECUTOR)) revert IncompatibleExecutorModule(executor);

        SentinelListLib.SentinelList storage executors = _getAccountStorage().executors;
        executors.push(executor);
        IExecutor(executor).onInstall(data);
    }

    function _uninstallExecutor(address executor, bytes calldata data) internal virtual {
        SentinelListLib.SentinelList storage executors = _getAccountStorage().executors;
        (address prev, bytes memory disableModuleData) = abi.decode(data, (address, bytes));
        executors.pop(prev, executor);
        IExecutor(executor).onUninstall(disableModuleData);
    }

    // /////////////////////////////////////////////////////
    // //  Manage Hook
    // ////////////////////////////////////////////////////

    function _installHook(address hook, bytes calldata data) internal virtual {
        address currentHook = _getHook();
        if (currentHook != address(0)) {
            revert HookAlreadyInstalled(currentHook);
        }
        _setHook(hook);
        IHook(hook).onInstall(data);
    }

    function _uninstallHook(address hook, bytes calldata data) internal virtual {
        _setHook(address(0));
        IHook(hook).onUninstall(data);
    }

    function _setHook(address hook) internal virtual {
        _getAccountStorage().hook = IHook(hook);
    }

    function _getHook() internal view returns (address hook) {
        hook = address(_getAccountStorage().hook);
    }

    function getActiveHook() external view returns (address hook) {
        return _getHook();
    }

    // /////////////////////////////////////////////////////
    // //  Query for installed modules
    // ////////////////////////////////////////////////////

    function _isValidatorInstalled(address validator) internal view virtual returns (bool) {
        SentinelListLib.SentinelList storage validators = _getAccountStorage().validators;
        return validators.contains(validator);
    }

    function _isExecutorInstalled(address executor) internal view virtual returns (bool) {
        SentinelListLib.SentinelList storage executors = _getAccountStorage().executors;
        return executors.contains(executor);
    }

    function _isHookInstalled(address hook) internal view returns (bool) {
        return _getHook() == hook;
    }

    function _isAlreadyInitialized() internal view virtual returns (bool) {
        // account module storage
        AccountStorage storage ams = _getAccountStorage();
        return ams.validators.alreadyInitialized();
    }

    function _getValidatorsPaginated(
        address cursor,
        uint256 size
    ) private view returns (address[] memory array, address next) {
        SentinelListLib.SentinelList storage validators = _getAccountStorage().validators;
        return validators.getEntriesPaginated(cursor, size);
    }

    function _getExecutorsPaginated(
        address cursor,
        uint256 size
    ) private view returns (address[] memory array, address next) {
        SentinelListLib.SentinelList storage executors = _getAccountStorage().executors;
        return executors.getEntriesPaginated(cursor, size);
    }

    // /////////////////////////////////////////////////////
    // //  Manage FALLBACK
    // ////////////////////////////////////////////////////

    function _installFallbackHandler(address handler, bytes calldata initData) internal virtual {
        if (_isFallbackHandlerInstalled()) revert FallbackHandlerAlreadyInstalled();
        _getAccountStorage().fallbackHandler = handler;
        IFallback(handler).onInstall(initData);
    }

    function _uninstallFallbackHandler(address fallbackHandler, bytes calldata initData) internal virtual {
        address currentFallback = _getAccountStorage().fallbackHandler;
        if (currentFallback != fallbackHandler) revert InvalidModule(fallbackHandler);
        _getAccountStorage().fallbackHandler = address(0);
        IFallback(currentFallback).onUninstall(initData);
    }

    function _isFallbackHandlerInstalled() internal view virtual returns (bool) {
        return _getAccountStorage().fallbackHandler != address(0);
    }

    function _isFallbackHandlerInstalled(address handler) internal view virtual returns (bool) {
        return _getAccountStorage().fallbackHandler == handler;
    }

    function getActiveFallbackHandler() external view virtual returns (address) {
        return _getAccountStorage().fallbackHandler;
    }

    // FALLBACK
    fallback() external payable override(Receiver) receiverFallback {
        address handler = _getAccountStorage().fallbackHandler;
        if (handler == address(0)) revert();
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            // When compiled with the optimizer, the compiler relies on a certain assumptions on how
            // the
            // memory is used, therefore we need to guarantee memory safety (keeping the free memory
            // point 0x40 slot intact,
            // not going beyond the scratch space, etc)
            // Solidity docs: https://docs.soliditylang.org/en/latest/assembly.html#memory-safety
            function allocate(length) -> pos {
                pos := mload(0x40)
                mstore(0x40, add(pos, length))
            }

            let calldataPtr := allocate(calldatasize())
            calldatacopy(calldataPtr, 0, calldatasize())

            // The msg.sender address is shifted to the left by 12 bytes to remove the padding
            // Then the address without padding is stored right after the calldata
            let senderPtr := allocate(20)
            mstore(senderPtr, shl(96, caller()))

            // Add 20 bytes for the address appended add the end
            let success := call(gas(), handler, 0, calldataPtr, add(calldatasize(), 20), 0, 0)

            let returnDataPtr := allocate(returndatasize())
            returndatacopy(returnDataPtr, 0, returndatasize())
            if iszero(success) {
                revert(returnDataPtr, returndatasize())
            }
            return(returnDataPtr, returndatasize())
        }
        /* solhint-enable no-inline-assembly */
    }
}

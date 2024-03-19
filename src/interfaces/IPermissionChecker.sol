// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPermissionChecker {
    
    function checkPermissionForSmartAccount(
        address smartAccount,
        bytes calldata permissionDataFromContext
    ) external view returns (bytes32 permissionPrefix);
    
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IUserOpConstructor, PackedUserOperation} from "./IUserOperationConstructor.sol";

contract BiconomyUserOpConstructor is IUserOpConstructor {

    function getNonceWithContext(
		bytes calldata permissionsContext
	) external view returns (uint256) {
        permissionsContext;
    }
  
    function getCallDataWithContext(
    	bytes calldata permissionsContext,
		executionObject[] calldata executions
	) external view returns (bytes memory callDataWithContext) {
        permissionsContext;
        executions;
        // just random stuff yet
        callDataWithContext = abi.encode(permissionsContext, executions);
    }
    
    function getSignatureWithContext(
	  bytes calldata permissionsContext,
	  PackedUserOperation calldata userOp,
	  bytes calldata rawSignature
	) external returns (bytes memory signature) {
        permissionsContext;
        userOp;
        rawSignature;
    }
}
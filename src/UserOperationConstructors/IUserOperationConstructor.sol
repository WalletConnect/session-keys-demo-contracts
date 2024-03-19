// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";

interface IUserOpConstructor {

	struct executionObject {
		address destination;
		uint256 value;
		bytes callData;
	}

	function getNonceWithContext(
		bytes calldata permissionsContext
	) external view returns (uint256);
	
	/**
	 * @dev Returns the calldata for the user operation, 
	 * given the permissions context and the executions.
	 */
    function getCallDataWithContext(
    	bytes calldata permissionsContext,
		executionObject[] calldata executions
	) external view returns (bytes memory);
    
    function getSignatureWithContext(
	  bytes calldata permissionsContext,
	  PackedUserOperation calldata userOp,
	  bytes calldata rawSignature
	) external returns (bytes memory signature);

}
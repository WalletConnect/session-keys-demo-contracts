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
		address smartAccount,
		bytes calldata permissionsContext
	) external view returns (uint256);
	
	/**
	 * @dev Returns the calldata for the user operation, 
	 * given the permissions context and the executions.
	 */
    function getCallDataWithContext(
		address smartAccount,
		executionObject[] calldata executions,
    	bytes calldata permissionsContext
	) external view returns (bytes memory);
    
    function getSignatureWithContext(
	  address smartAccount,
	  PackedUserOperation calldata userOp,
	  bytes calldata rawSignature,
	  bytes calldata permissionsContext
	) external returns (bytes memory signature);

}
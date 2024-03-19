// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IUserOpConstructor, PackedUserOperation} from "./IUserOperationConstructor.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

contract BiconomyUserOpConstructor is IUserOpConstructor {

    IEntryPoint public immutable entryPoint;

    constructor(address _entryPoint) {
        entryPoint = IEntryPoint(_entryPoint);
    }

    function getNonceWithContext(
        address smartAccount,
		bytes calldata permissionsContext
	) external view returns (uint256 nonce) {
        address validator = address(bytes20(permissionsContext[0:20]));
        uint192 key = uint192(bytes24(bytes20(address(validator))));
        nonce = entryPoint.getNonce(address(smartAccount), key);
    }
  
    function getCallDataWithContext(
        address smartAccount,
		executionObject[] calldata executions,
        bytes calldata permissionsContext
	) external view returns (bytes memory callDataWithContext) {
        permissionsContext;
        executions;
        // just random stuff yet
        callDataWithContext = abi.encode(permissionsContext, executions);
    }
    
    function getSignatureWithContext(
	  address smartAccount,
	  PackedUserOperation calldata userOp,
	  bytes calldata rawSignature,
      bytes calldata permissionsContext
	) external returns (bytes memory signature) {
        permissionsContext;
        userOp;
        rawSignature;
    }
}
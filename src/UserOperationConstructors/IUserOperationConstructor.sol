// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { Execution } from "erc7579/interfaces/IERC7579Account.sol";

interface IUserOpConstructor {
    function getNonceWithContext(
        address smartAccount,
        bytes calldata permissionsContext
    )
        external
        view
        returns (uint256);

    /**
     * @dev Returns the calldata for the user operation,
     * given the permissions context and the executions.
     * @param executions are just standard (destination, value, callData) sets
     * as the dApp that calls this method is unaware of SA's execution interfaces
     * Execution from 7579 is used here as it is exactly this basic structure.
     */
    function getCallDataWithContext(
        address smartAccount,
        Execution[] calldata executions,
        bytes calldata permissionsContext
    )
        external
        view
        returns (bytes memory);

    function getSignatureWithContext(
        address smartAccount,
        PackedUserOperation calldata userOp,
        bytes calldata permissionsContext
    )
        external
        returns (bytes memory signature);
}

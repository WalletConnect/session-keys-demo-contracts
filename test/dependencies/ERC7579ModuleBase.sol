// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IModule } from "erc7579/interfaces/IERC7579Module.sol";

abstract contract ERC7579ModuleBase is IModule {
    uint256 constant TYPE_VALIDATOR = 1;
    uint256 constant TYPE_EXECUTOR = 2;
    uint256 constant TYPE_FALLBACK = 3;
    uint256 constant TYPE_HOOK = 4;
}

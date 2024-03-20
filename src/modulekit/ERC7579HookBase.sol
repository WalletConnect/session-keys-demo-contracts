// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IHook as IERC7579Hook } from "erc7579/interfaces/IERC7579Module.sol";
import { ERC7579ModuleBase } from "./ERC7579ModuleBase.sol";

abstract contract ERC7579HookBase is IERC7579Hook, ERC7579ModuleBase { }

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { SentinelListLib } from "sentinellist/SentinelList.sol";
import { IHook } from "../modules/IHook.sol";

interface IStorage {
    /// @custom:storage-location erc7201:biconomy.storage.SmartAccount
    struct AccountStorage {
        // linked list of validators. List is initialized by initializeAccount()
        SentinelListLib.SentinelList validators;
        // linked list of executors. List is initialized by initializeAccount()
        SentinelListLib.SentinelList executors;
        // single fallback handler for all fallbacks
        address fallbackHandler;
        IHook hook;
    }
}

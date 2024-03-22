// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import "forge-std/console2.sol";
import "forge-std/Script.sol";

import "src/Safe7579Adapter/SafeERC7579.sol";

contract DeploySafe7579 is Script {
    SafeERC7579 safe7579;

    function run() public {
        vm.startBroadcast();

        safe7579 = new SafeERC7579();

        vm.stopBroadcast();
    }
}

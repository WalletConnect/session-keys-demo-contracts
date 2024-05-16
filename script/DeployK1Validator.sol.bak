// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

//import "forge-std/console2.sol";
import "forge-std/Script.sol";

import "src/test/BiconomyERC7579/modules/validators/R1Validator.sol";

contract DeployK1Validator is Script {
    R1Validator k1Validator;

    function run() public {
        vm.startBroadcast();

        k1Validator = new R1Validator();

        vm.stopBroadcast();
    }
}

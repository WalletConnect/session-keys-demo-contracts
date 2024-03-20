// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import "forge-std/console2.sol";
import "forge-std/Script.sol";

import "../src/UserOperationConstructors/BiconomyUserOperationConstructor.sol";

contract DeployBiconomyUserOpConstructor is Script {
    BiconomyUserOpConstructor bicoUserOpConstructooor;

    function run() public {
        vm.startBroadcast();

        bicoUserOpConstructooor =
            new BiconomyUserOpConstructor(0x0000000071727De22E5E9d8BAf0edAc6f37da032);

        vm.stopBroadcast();
    }
}

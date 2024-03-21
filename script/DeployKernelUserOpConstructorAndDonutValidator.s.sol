pragma solidity ^0.8.20;

import "forge-std/console.sol";
import "forge-std/Script.sol";
import {KernelV3UserOpConstructor} from "src/UserOperationConstructors/KernelV3UserOpConstructor.sol";
import {DonutValidator, IDonut} from "src/DonutValidator/DonutValidator.sol";

contract KernelAndDonut is Script {
    function run() public {
        vm.startBroadcast();
        KernelV3UserOpConstructor const = new KernelV3UserOpConstructor{salt:0}(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
        console.log("Constructor :", address(const));
        DonutValidator donut = new DonutValidator{salt:0}(IDonut(0x2d29E46018Da800463152c7f0f3dfcE3047d6B2C));
        console.log("DonutValidator :", address(donut));

        vm.stopBroadcast();
    }
}

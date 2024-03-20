// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "erc7579/interfaces/IERC7579Account.sol";
import "erc7579/lib/ModeLib.sol";
import "erc7579/lib/ExecutionLib.sol";
import { TestBaseUtil } from "./ERC7579PV_Base.t.sol";

import "forge-std/console2.sol";

//CallType constant CALLTYPE_STATIC = CallType.wrap(0xFE);

contract ERC7579PermissionValidatorTest is ERC7579PermissionValidatorTestBaseUtil {

    function setUp() public override {
        super.setUp();
        
        deal(address(bicoUserSA), 1 ether);
    }
}

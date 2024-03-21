// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "erc7579/interfaces/IERC7579Account.sol";
import "erc7579/lib/ModeLib.sol";
import "erc7579/lib/ExecutionLib.sol";
import { ERC7579PermissionValidatorTestBaseUtil } from "./ERC7579PV_Base.t.sol";

import "forge-std/console2.sol";

//CallType constant CALLTYPE_STATIC = CallType.wrap(0xFE);

contract ERC7579PermissionValidatorTest is ERC7579PermissionValidatorTestBaseUtil {

    uint256 internal constant MODULE_TYPE_VALIDATOR = 1;

    function setUp() public override {
        super.setUp();
    }

    function test_test() public {
        console2.log(bicoUserSA.accountId());
    }

    function  test_enable7579PermissionValidator() public {
        PackedUserOperation memory userOp = getDefaultUserOp(
            address(bicoUserSA), 
            address(defaultValidator)
        );

        bytes memory userOpCalldata = abi.encodeCall(
            IERC7579Account.installModule,
            (
                MODULE_TYPE_VALIDATOR,
                address(permissionValidator),
                ""
            )
        );

        userOp.callData = userOpCalldata;
        bytes32 userOpHash = entrypoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer1.key, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        userOp.signature = signature;

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));

        assertEq(
            bicoUserSA.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(permissionValidator), ""),
            true
        );
    }

    

}

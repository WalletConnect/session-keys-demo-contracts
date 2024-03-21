// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "erc7579/interfaces/IERC7579Account.sol";
import "erc7579/lib/ModeLib.sol";
import "erc7579/lib/ExecutionLib.sol";
//import { TestBaseUtil, MockTarget, MockFallback } from "./Base.t.sol";
import { TestPermissionValidatorBaseUtil, MockTarget } from "./Base.t.sol";
import "src/PermissionManager/PermissionValidator.sol";
import "forge-std/console2.sol";
import "src/PermissionManager/PolicyConfig.sol";

//CallType constant CALLTYPE_STATIC = CallType.wrap(0xFE);

contract PermissionValidatorTest is TestPermissionValidatorBaseUtil {
    MockTarget target;

    function setUp() public override {
        super.setUp();
        target = new MockTarget();
        deal(address(safe), 1 ether);
    }

    modifier alreadyInitialized(bool initNow) {
        if (initNow) {
            test_initializeAccount();
        }
        _;
    }

    function test_initializeAccount() public {
        PackedUserOperation memory userOp = getDefaultUserOp(address(safe), address(0));

        // Create calldata for the account to execute
        bytes memory setValueOnTarget = abi.encodeCall(MockTarget.set, 777);

        // Encode the call into the calldata for the userOp
        bytes memory userOpCalldata = abi.encodeCall(
            IERC7579Account.execute,
            (
                ModeLib.encodeSimpleSingle(),
                ExecutionLib.encodeSingle(address(target), uint256(0), setValueOnTarget)
            )
        );
        userOp.initCode = userOpInitCode;
        userOp.callData = userOpCalldata;

        bytes32 safeOp = safe7579.getOperationHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer1.key, safeOp);

        userOp.signature = abi.encodePacked(userOp.signature, r, s, v);
        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));

        // Assert that the value was set ie that execution was successful
        assertTrue(target.value() == 777);
        userOpInitCode = "";
    }

    function test_execSingle(bool withInitializedAccount)
        public
        alreadyInitialized(withInitializedAccount)
    {
        // Enable permission
        // bytes enablePermissionData = defaultValidator.parseData();

        // Create calldata for the account to execute
        PolicyConfig[] memory policy = new PolicyConfig[](1);
        policy[0] = PolicyConfigLib.pack(sudoPolicy, toFlag(1));

        bytes memory registerPermssionCalldata = abi.encodeCall(
            defaultValidator.registerPermission,
            (
                defaultValidator.getNonce(address(safe)),
                toFlag(1),
                ecdsaSigner,
                ValidAfter.wrap(0),
                ValidUntil.wrap(0),
                policy,
                abi.encodePacked(signer2.addr),
                new bytes[](1)
            )
        );

        bytes32 permissionId = defaultValidator.getPermissionId(
            toFlag(1),
            ecdsaSigner,
            ValidAfter.wrap(0),
            ValidUntil.wrap(0),
            policy,
            abi.encodePacked(signer2.addr),
            new bytes[](1)
        );

        // Encode the call into the calldata for the userOp
        bytes memory userOpCalldata = abi.encodeCall(
            IERC7579Account.execute,
            (
                ModeLib.encodeSimpleSingle(),
                ExecutionLib.encodeSingle(
                    address(defaultValidator), uint256(0), registerPermssionCalldata
                    )
            )
        );

        PackedUserOperation memory userOp = getDefaultUserOp(address(safe), address(0));
        userOp.initCode = userOpInitCode;
        userOp.callData = userOpCalldata;

        bytes32 safeOp = safe7579.getOperationHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer1.key, safeOp);

        userOp.signature = abi.encodePacked(userOp.signature, r, s, v);

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));

        // Create calldata for the account to execute
        bytes memory setValueOnTarget = abi.encodeCall(MockTarget.set, 1337);

        // Encode the call into the calldata for the userOp
        bytes memory userOpCalldata2 = abi.encodeCall(
            IERC7579Account.execute,
            (
                ModeLib.encodeSimpleSingle(),
                ExecutionLib.encodeSingle(address(target), uint256(0), setValueOnTarget)
            )
        );
        PackedUserOperation memory userOp2 =
            getDefaultUserOp(address(safe), address(defaultValidator));
        userOp2.callData = userOpCalldata2;

        bytes32 userOp2Hash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", entrypoint.getUserOpHash(userOp2))
        );
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(signer2.key, userOp2Hash);

        userOp2.signature = abi.encodePacked(permissionId, r2, s2, v2);

        // Create userOps array
        PackedUserOperation[] memory userOps2 = new PackedUserOperation[](1);
        userOps2[0] = userOp2;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps2, payable(address(0x69)));

        // Assert that the value was set ie that execution was successful
        assertTrue(target.value() == 1337);
    }
}

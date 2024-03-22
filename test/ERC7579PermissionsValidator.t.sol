// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "erc7579/interfaces/IERC7579Account.sol";
import "erc7579/lib/ModeLib.sol";
import "erc7579/lib/ExecutionLib.sol";
import { TestERC7579PermissionsValidatorUtil, MockTarget } from "./Base.t.sol";
import "src/PermissionManager/PolicyConfig.sol";
import "src/ERC7579PermissionsValidator/ERC7579PermissionsValidator.sol";
import "src/Safe7579Adapter/SafeERC7579.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ERC7579PermissionValidatorTest is TestERC7579PermissionsValidatorUtil {
    MockTarget target;

    using MessageHashUtils for bytes32;
    using ECDSA for bytes32;

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
        PackedUserOperation memory userOpEnablePermission =
            getDefaultUserOp(address(safe), address(0));

        bytes memory permissionEnableData = abi.encodePacked(
            bytes1(uint8(1)),
            bytes8(uint64(block.chainid)),
            keccak256(
                abi.encodePacked(
                    ValidUntil.wrap(0),
                    ValidAfter.wrap(0),
                    address(validationAlgorithm),
                    abi.encodePacked(signer2.addr),
                    address(sudoPolicy),
                    ""
                )
            )
        );

        bytes32 messageHash =
            entrypoint.getUserOpHash(userOpEnablePermission).toEthSignedMessageHash();

        (uint8 vSigner2, bytes32 rSigner2, bytes32 sSigner2) = vm.sign(signer2.key, messageHash);

        userOpEnablePermission.signature = abi.encodePacked(
            bytes1(uint8(1)),
            abi.encode(
                uint256(0),
                ValidUntil.wrap(0),
                ValidAfter.wrap(0),
                validationAlgorithm,
                abi.encodePacked(signer2.addr),
                address(sudoPolicy),
                "",
                permissionEnableData,
                getSignedBytes(permissionEnableData),
                abi.encodePacked(rSigner2, sSigner2, vSigner2)
            )
        );

        bytes memory registerPermssionCalldata = abi.encodeCall(
            defaultValidator.validateUserOp,
            (userOpEnablePermission, entrypoint.getUserOpHash(userOpEnablePermission))
        );

        userOpEnablePermission.callData = registerPermssionCalldata;

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

        // // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // // Send the userOp to the entrypoint
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

        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(
            signer2.key,
            keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n32", entrypoint.getUserOpHash(userOp2)
                )
            )
        );

        userOp2.signature = abi.encodePacked(
            bytes1(0x00), abi.encode(getPermissionDigest(), abi.encodePacked(r3, s3, v3))
        );

        // Create userOps array
        PackedUserOperation[] memory userOps2 = new PackedUserOperation[](1);
        userOps2[0] = userOp2;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps2, payable(address(0x69)));

        // Assert that the value was set ie that execution was successful
        assertTrue(target.value() == 1337);
    }

    function getSignedBytes(bytes memory permissionEnableData)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v4, bytes32 r4, bytes32 s4) = vm.sign(
            signer1.key,
            keccak256(
                EIP712.encodeMessageData(
                    0x269ffd8f804c7a2323fe35ba601aa125be5704798f767b429d790a4aed858739,
                    0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca,
                    abi.encode(
                        keccak256(
                            abi.encode(keccak256(permissionEnableData).toEthSignedMessageHash())
                        )
                    )
                )
            )
        );
        return abi.encodePacked(address(0), r4, s4, v4);
    }

    function getPermissionDigest() internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                ValidUntil.wrap(0),
                ValidAfter.wrap(0),
                address(validationAlgorithm),
                abi.encodePacked(signer2.addr),
                address(sudoPolicy),
                ""
            )
        );
    }
}

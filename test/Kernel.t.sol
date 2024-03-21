// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import {
    ValidationId,
    Kernel,
    IEntryPoint,
    IHook,
    ExecLib,
    PackedUserOperation as Ops
} from "kernel_v3/Kernel.sol";
import { SimpleProxy, MockCallee } from "kernel_v3/sdk/TestBase/KernelTestBase.sol";
import { EntryPointLib } from "kernel_v3/sdk/TestBase/erc4337Util.sol";
import {
    KernelV3UserOpConstructor,
    Execution,
    PackedUserOperation
} from "src/UserOperationConstructors/KernelV3UserOpConstructor.sol";
import { MockValidator } from "kernel_v3/mock/MockValidator.sol";

contract KernelTest is Test {
    IEntryPoint entrypoint;
    Kernel kernel;
    KernelV3UserOpConstructor kernelConstructor;
    MockValidator mockValidator;
    MockCallee mockCallee;

    function encodeExecute(
        address _to,
        uint256 _amount,
        bytes memory _data
    )
        internal
        view
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            kernel.execute.selector,
            ExecLib.encodeSimpleSingle(),
            ExecLib.encodeSingle(_to, _amount, _data)
        );
    }

    function setUp() public {
        entrypoint = IEntryPoint(EntryPointLib.deploy());
        Kernel impl = new Kernel(entrypoint);
        kernel = Kernel(payable(address(new SimpleProxy(address(impl)))));
        kernelConstructor = new KernelV3UserOpConstructor(address(entrypoint));
        mockValidator = new MockValidator();
        kernel.initialize(
            ValidationId.wrap(bytes21(abi.encodePacked(bytes1(0x01), address(mockValidator)))),
            IHook(address(0)),
            hex"deadbeef",
            hex""
        );
    }

    function testConsruct() external {
        vm.deal(address(kernel), 10e18);
        MockValidator newMock = new MockValidator();
        bytes memory permissionsContext = abi.encodePacked(
            bytes1(0x01),
            bytes1(0x01),
            address(newMock),
            address(0),
            abi.encode(
                "newValidatorEnableData",
                hex"",
                abi.encodePacked(Kernel.execute.selector),
                "enableSig",
                hex"" // extraData
            )
        );
        uint256 nonce = kernelConstructor.getNonceWithContext(address(kernel), permissionsContext);
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({
            target: address(mockCallee),
            value: 0,
            callData: abi.encodeWithSelector(MockCallee.setValue.selector, uint256(123))
        });
        bytes memory callData = kernelConstructor.getCallDataWithContext(
            address(kernel), executions, permissionsContext
        );
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: nonce,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1_000_000), uint128(1_000_000))),
            preVerificationGas: 1_000_000,
            gasFees: bytes32(abi.encodePacked(uint128(0), uint128(0))),
            paymasterAndData: hex"",
            signature: hex""
        });
        op.signature =
            kernelConstructor.getSignatureWithContext(address(kernel), op, permissionsContext);
        Ops[] memory ops = new Ops[](1);
        ops[0] = Ops({
            sender: op.sender,
            nonce: op.nonce,
            initCode: op.initCode,
            callData: op.callData,
            accountGasLimits: op.accountGasLimits,
            preVerificationGas: op.preVerificationGas,
            gasFees: op.gasFees,
            paymasterAndData: op.paymasterAndData,
            signature: op.signature
        });
        mockValidator.sudoSetValidSig("enableSig");
        newMock.sudoSetSuccess(true);
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }
}

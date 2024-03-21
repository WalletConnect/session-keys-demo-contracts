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
import { ECDSA } from "solady/src/utils/ECDSA.sol";
import {
    KernelV3UserOpConstructor,
    Execution,
    PackedUserOperation
} from "src/UserOperationConstructors/KernelV3UserOpConstructor.sol";
import { MockValidator } from "kernel_v3/mock/MockValidator.sol";
import { DonutValidator, IDonut} from "src/DonutValidator/DonutValidator.sol";

contract MockDonut is IDonut {
    mapping(address => uint256) public balance;
    function purchase(uint256 amount) external payable {
        balance[msg.sender] += amount;
    }
}

contract KernelTest is Test {
    IEntryPoint entrypoint;
    Kernel kernel;
    KernelV3UserOpConstructor kernelConstructor;
    MockValidator mockValidator;
    DonutValidator donutValidator;
    MockDonut donut;
    MockCallee mockCallee;
    address signer;
    uint256 signerKey;

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
        donut = new MockDonut();
        donutValidator = new DonutValidator(donut);
        (signer, signerKey) = makeAddrAndKey("donutSigner");
    }

    function testPolicyWithLessThanLimit() external {
        vm.deal(address(kernel), 10e18);
        bytes memory permissionsContext = abi.encodePacked(
            bytes1(0x01),
            bytes1(0x01),
            address(donutValidator),
            address(0),
            abi.encode(
                abi.encodePacked(signer, uint256(10000)),
                hex"",
                abi.encodePacked(Kernel.execute.selector),
                "enableSig"
            )
        );
        uint256 nonce = kernelConstructor.getNonceWithContext(address(kernel), permissionsContext);
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({
            target: address(donut),
            value: 0,
            callData: abi.encodeWithSelector(IDonut.purchase.selector, uint256(123))
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
            signature: hex"73c3ac716c487ca34bb858247b5ccf1dc354fbaabdd089af3b2ac8e78ba85a4959a2d76250325bd67c11771c31fccda87c33ceec17cc0de912690521bb95ffcb1b"
        });
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
        bytes32 userOpHash = entrypoint.getUserOpHash(ops[0]);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, ECDSA.toEthSignedMessageHash(userOpHash));
        op.signature = abi.encodePacked(r, s, v);
        ops[0].signature = kernelConstructor.getSignatureWithContext(address(kernel), op, permissionsContext);

        mockValidator.sudoSetValidSig("enableSig");
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }
    function testPolicyWithMoreThanLimit() external {
        vm.deal(address(kernel), 10e18);
        bytes memory permissionsContext = abi.encodePacked(
            bytes1(0x01),
            bytes1(0x01),
            address(donutValidator),
            address(0),
            abi.encode(
                abi.encodePacked(signer, uint256(10000)),
                hex"",
                abi.encodePacked(Kernel.execute.selector),
                "enableSig"
            )
        );
        uint256 nonce = kernelConstructor.getNonceWithContext(address(kernel), permissionsContext);
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({
            target: address(donut),
            value: 0,
            callData: abi.encodeWithSelector(IDonut.purchase.selector, uint256(10001))
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
            signature: hex"73c3ac716c487ca34bb858247b5ccf1dc354fbaabdd089af3b2ac8e78ba85a4959a2d76250325bd67c11771c31fccda87c33ceec17cc0de912690521bb95ffcb1b"
        });
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
        bytes32 userOpHash = entrypoint.getUserOpHash(ops[0]);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, ECDSA.toEthSignedMessageHash(userOpHash));
        op.signature = abi.encodePacked(r, s, v);
        ops[0].signature = kernelConstructor.getSignatureWithContext(address(kernel), op, permissionsContext);

        mockValidator.sudoSetValidSig("enableSig");
        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }
}

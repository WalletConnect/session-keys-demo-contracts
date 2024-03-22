// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import { SafeERC7579 } from "src/Safe7579Adapter/SafeERC7579.sol";
import { ModuleManager } from "src/Safe7579Adapter/core/ModuleManager.sol";
import { MockValidator } from "src/modulekit/mocks/MockValidator.sol";
//import { MockExecutor } from "./mocks/MockExecutor.sol";
//import { MockFallback } from "./mocks/MockFallback.sol";
import { MockTarget } from "src/modulekit/mocks/MockTarget.sol";

import { Safe } from "@safe-global/safe-contracts/contracts/Safe.sol";
import { SafeProxyFactory } from
    "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { LibClone } from "solady/src/utils/LibClone.sol";
import "src/Safe7579Adapter/utils/Launchpad.sol";
import "src/PermissionManager/policies/SudoPolicy.sol";
import { Solarray } from "solarray/Solarray.sol";
import "src/modulekit/EntryPoint.sol";
import "src/PermissionManager/signers/ECDSASigner.sol";
import { PermissionValidator } from "src/PermissionManager/PermissionValidator.sol";
import { ERC7579PermissionsValidator } from
    "src/ERC7579PermissionsValidator/ERC7579PermissionsValidator.sol";

import { Secp256K1SigValidationAlgorithm } from
    "src/ERC7579PermissionsValidator/SigValidation/Secp256K1.sol";

contract TestSafeERC7579 is Test {
    SafeERC7579 safe7579;
    Safe singleton;
    Safe safe;
    SafeProxyFactory safeProxyFactory;
    Safe7579Launchpad launchpad;

    Account signer1 = makeAccount("signer1");
    Account signer2 = makeAccount("signer2");

    // keccak256("SafeMessage(bytes message)");
    bytes32 constant SAFE_MSG_TYPEHASH =
        0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;

    function initCode(
        bytes memory initializer,
        bytes32 salt
    )
        internal
        view
        returns (bytes memory _initCode)
    {
        _initCode = abi.encodePacked(
            address(safeProxyFactory),
            abi.encodeCall(
                SafeProxyFactory.createProxyWithNonce,
                (address(singleton), initializer, uint256(salt))
            )
        );
    }

    function getDefaultUserOp(
        address account,
        address validator
    )
        internal
        view
        returns (PackedUserOperation memory userOp)
    {
        userOp = PackedUserOperation({
            sender: account,
            nonce: safe7579.getNonce(account, validator),
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            preVerificationGas: 2e6,
            gasFees: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            paymasterAndData: bytes(""),
            signature: abi.encodePacked(uint48(0), uint48(0))
        });
    }
}

contract TestBaseUtil is Test {
    SafeERC7579 safe7579;
    Safe singleton;
    Safe safe;
    SafeProxyFactory safeProxyFactory;
    Safe7579Launchpad launchpad;

    MockValidator defaultValidator;
    //MockExecutor defaultExecutor;

    Account signer1 = makeAccount("signer1");
    Account signer2 = makeAccount("signer2");

    IEntryPoint entrypoint;
    bytes userOpInitCode;

    function setUp() public virtual {
        // Set up EntryPoint
        entrypoint = etchEntrypoint();
        singleton = new Safe();
        safeProxyFactory = new SafeProxyFactory();
        safe7579 = new SafeERC7579();
        launchpad = new Safe7579Launchpad(address(safe7579));

        // Set up Modules
        defaultValidator = new MockValidator();
        //defaultExecutor = new MockExecutor();

        bytes32 salt;

        bytes memory initData = "";
        ISafe7579Init.ModuleInit[] memory validators = new ISafe7579Init.ModuleInit[](1);
        validators[0] =
            ISafe7579Init.ModuleInit({ module: address(defaultValidator), initData: initData });

        ISafe7579Init.ModuleInit[] memory executors = new ISafe7579Init.ModuleInit[](0);
        ISafe7579Init.ModuleInit[] memory fallbacks = new ISafe7579Init.ModuleInit[](0);
        ISafe7579Init.ModuleInit[] memory hooks = new ISafe7579Init.ModuleInit[](0);

        bytes memory initializer = launchpad.getInitCode({
            signers: Solarray.addresses(signer1.addr, signer2.addr),
            threshold: 2,
            validators: validators,
            executors: executors,
            fallbacks: fallbacks,
            hooks: hooks
        });
        // computer counterfactual address for SafeProxy
        safe = Safe(
            payable(
                launchpad.predictSafeAddress({
                    singleton: address(singleton),
                    safeProxyFactory: address(safeProxyFactory),
                    creationCode: safeProxyFactory.proxyCreationCode(),
                    salt: salt,
                    initializer: initializer
                })
            )
        );
        userOpInitCode = initCode(initializer, salt);
    }

    function initCode(
        bytes memory initializer,
        bytes32 salt
    )
        internal
        view
        returns (bytes memory _initCode)
    {
        _initCode = abi.encodePacked(
            address(safeProxyFactory),
            abi.encodeCall(
                SafeProxyFactory.createProxyWithNonce,
                (address(singleton), initializer, uint256(salt))
            )
        );
    }

    function getDefaultUserOp(
        address account,
        address validator
    )
        internal
        view
        returns (PackedUserOperation memory userOp)
    {
        userOp = PackedUserOperation({
            sender: account,
            nonce: safe7579.getNonce(account, validator),
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            preVerificationGas: 2e6,
            gasFees: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            paymasterAndData: bytes(""),
            signature: abi.encodePacked(hex"41414141")
        });
    }
}

contract TestERC7579PermissionsValidatorUtil is TestSafeERC7579 {
    Secp256K1SigValidationAlgorithm validationAlgorithm;
    ERC7579PermissionsValidator defaultValidator;

    SudoPolicy sudoPolicy;

    IEntryPoint entrypoint;
    bytes userOpInitCode;

    function setUp() public virtual {
        // Set up EntryPoint
        entrypoint = etchEntrypoint();
        singleton = new Safe();
        safeProxyFactory = new SafeProxyFactory();
        safe7579 = new SafeERC7579();
        launchpad = new Safe7579Launchpad(address(safe7579));
        validationAlgorithm = new Secp256K1SigValidationAlgorithm();
        // Set up Modules
        defaultValidator = new ERC7579PermissionsValidator();
        //defaultExecutor = new MockExecutor();
        sudoPolicy = new SudoPolicy();
        bytes32 salt;

        ISafe7579Init.ModuleInit[] memory validators = new ISafe7579Init.ModuleInit[](1);
        validators[0] =
            ISafe7579Init.ModuleInit({ module: address(defaultValidator), initData: bytes("") });

        ISafe7579Init.ModuleInit[] memory executors = new ISafe7579Init.ModuleInit[](0);
        ISafe7579Init.ModuleInit[] memory fallbacks = new ISafe7579Init.ModuleInit[](0);
        ISafe7579Init.ModuleInit[] memory hooks = new ISafe7579Init.ModuleInit[](0);

        bytes memory initializer = launchpad.getInitCode({
            signers: Solarray.addresses(signer1.addr),
            threshold: 1,
            validators: validators,
            executors: executors,
            fallbacks: fallbacks,
            hooks: hooks
        });
        // computer counterfactual address for SafeProxy
        safe = Safe(
            payable(
                launchpad.predictSafeAddress({
                    singleton: address(singleton),
                    safeProxyFactory: address(safeProxyFactory),
                    creationCode: safeProxyFactory.proxyCreationCode(),
                    salt: salt,
                    initializer: initializer
                })
            )
        );

        vm.deal(address(safe), 1 ether);
        userOpInitCode = initCode(initializer, salt);
    }
}

contract TestPermissionValidatorBaseUtil is TestSafeERC7579 {
    ECDSASigner ecdsaSigner;
    PermissionValidator defaultValidator;
    //MockExecutor defaultExecutor;

    SudoPolicy sudoPolicy;

    IEntryPoint entrypoint;
    bytes userOpInitCode;

    function setUp() public virtual {
        // Set up EntryPoint
        entrypoint = etchEntrypoint();
        singleton = new Safe();
        safeProxyFactory = new SafeProxyFactory();
        safe7579 = new SafeERC7579();
        launchpad = new Safe7579Launchpad(address(safe7579));
        ecdsaSigner = new ECDSASigner();
        // Set up Modules
        defaultValidator = new PermissionValidator();
        //defaultExecutor = new MockExecutor();
        sudoPolicy = new SudoPolicy();
        bytes32 salt;

        ISafe7579Init.ModuleInit[] memory validators = new ISafe7579Init.ModuleInit[](1);
        validators[0] =
            ISafe7579Init.ModuleInit({ module: address(defaultValidator), initData: bytes("") });

        ISafe7579Init.ModuleInit[] memory executors = new ISafe7579Init.ModuleInit[](0);
        ISafe7579Init.ModuleInit[] memory fallbacks = new ISafe7579Init.ModuleInit[](0);
        ISafe7579Init.ModuleInit[] memory hooks = new ISafe7579Init.ModuleInit[](0);

        bytes memory initializer = launchpad.getInitCode({
            signers: Solarray.addresses(signer1.addr),
            threshold: 1,
            validators: validators,
            executors: executors,
            fallbacks: fallbacks,
            hooks: hooks
        });
        // computer counterfactual address for SafeProxy
        safe = Safe(
            payable(
                launchpad.predictSafeAddress({
                    singleton: address(singleton),
                    safeProxyFactory: address(safeProxyFactory),
                    creationCode: safeProxyFactory.proxyCreationCode(),
                    salt: salt,
                    initializer: initializer
                })
            )
        );

        vm.deal(address(safe), 1 ether);
        userOpInitCode = initCode(initializer, salt);
    }
}

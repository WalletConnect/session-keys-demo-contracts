// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import { SmartAccount } from "bico-sa/contracts/SmartAccount.sol";
import { R1Validator } from "bico-sa/contracts/modules/validators/R1Validator.sol";
import { AccountFactory } from "bico-sa/contracts/factory/AccountFactory.sol";

import "src/modulekit/EntryPoint.sol";

contract ERC7579PermissionValidatorTestBaseUtil is Test {

    SmartAccount bicoImplementation;
    SmartAccount bicoUserSA;
    R1Validator defaultValidator;
    AccountFactory bicoSAFactory;
    

    IEntryPoint entrypoint;

    Account signer1 = makeAccount("signer1");
    Account signer2 = makeAccount("signer2");

    function setUp() public virtual {

        entrypoint = etchEntrypoint();
        bicoImplementation = new SmartAccount();
        defaultValidator = new R1Validator();
        bicoSAFactory = new AccountFactory(address(bicoImplementation));

        bytes memory initialValidatorSetupData = ethers.solidityPacked(["address"], [signer1.addr]);

        uint256 deploymentIndex = 0;
        address bicoUserSAExpectedAddress = bicoSAFactory.getCounterFactualAddress(
            address(defaultValidator),
            initialValidatorSetupData,
            deploymentIndex
        );

        PackedUserOperation memory userOp = getDefaultUserOp(address(bicoUserSA), address(defaultValidator));
        userOp.initCode = initCode(address(defaultValidator), initialValidatorSetupData, deploymentIndex);

        bytes memory userOpHash = entrypoint.getUserOpHash(userOp);
        bytes memory userOpSignature = signer1.sign(userOpHash);

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));

        bicoUserSA = SmartAccount(payable(bicoUserSAExpectedAddress));
        console2.log("bicoUserSA: ", bicoUserSA.accountId());

    }

    function getDefaultUserOp(address sender, address validator) internal returns (PackedUserOperation memory userOp) {
        userOp = PackedUserOperation({
            sender: sender,
            nonce: getNonce(sender, validator),
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            preVerificationGas: 2e6,
            gasFees: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            paymasterAndData: bytes(""),
            signature: abi.encodePacked(hex"41414141")
        });
    }

    function getNonce(address account, address validator) internal returns (uint256 nonce) {
        uint192 key = uint192(bytes24(bytes20(address(validator))));
        nonce = entrypoint.getNonce(address(account), key);
    }

    function initCode(
        address initialValidatorSetupContract,
        bytes memory initialValidatorSetupData,
        uint256 index
    )
        internal
        view
        returns (bytes memory initCode)
    {
        initCode = abi.encodePacked(
            address(bicoSAFactory),
            abi.encodeCall(
                bicoSAFactory.createAccount,
                (
                    address(initialValidatorSetupContract), 
                    initialValidatorSetupData, 
                    index
                )
            )
        );
    }
}
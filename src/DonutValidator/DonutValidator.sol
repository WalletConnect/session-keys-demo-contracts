// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    IModule,
    IValidator,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "erc7579/interfaces/IERC7579Module.sol";
import "erc7579/interfaces/IERC7579Account.sol";
import { ECDSA } from "solady/src/utils/ECDSA.sol";
import "erc7579/lib/ExecutionLib.sol";
import "erc7579/lib/ModeLib.sol";

interface IDonut {
    function purchase(uint256 amount) external payable;
}

contract DonutValidator is IValidator {
    using ECDSA for bytes32;
    struct DonutPolicy {
        address signer;
        uint256 limit;
    }

    mapping(address => DonutPolicy) public policy;

    IDonut public donut;

    constructor(IDonut _donut) {
        donut = _donut;
    }

    function onInstall(bytes calldata data) external {
        address signer = address(bytes20(data[0:20]));
        uint256 limit = uint256(bytes32(data[20:52]));

        policy[msg.sender] = DonutPolicy({
            signer: signer,
            limit: limit
        });
    }

    function onUninstall(bytes calldata) external {
    }

    function isModuleType(uint256 moduleTypeId) external view returns(bool) {
        return moduleTypeId == 1;
    }

    function isInitialized(address smartAccount) external view returns(bool) {
        return policy[smartAccount].signer != address(0);
    }
    
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        returns (uint256) {
        bytes calldata callData = userOp.callData;
        require(bytes4(callData[0:4]) == IERC7579Account.execute.selector, "only execute");
        ModeCode mode = ModeCode.wrap(bytes32(callData[4:36]));
        (CallType ct, , ,) = ModeLib.decode(mode);
        require(ct == CALLTYPE_SINGLE, "only single");
        (address target, uint256 value , bytes calldata data) = ExecutionLib.decodeSingle(callData[100:]);
        require(target == address(donut), "only donut");
        require(bytes4(data[0:4]) == IDonut.purchase.selector, "only purshase");
        uint256 purchaseAmount = uint256(bytes32(data[4:36]));
        require( purchaseAmount <= policy[userOp.sender].limit, "over limit");
        policy[userOp.sender].limit -= purchaseAmount;
        address recovered = ECDSA.toEthSignedMessageHash(userOpHash).recover(userOp.signature);
        if(recovered != policy[userOp.sender].signer) {
            return 1;
        } else {
            return 0;
        }
    }

    /**
     * Validator can be used for ERC-1271 validation
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        returns (bytes4) {
        return 0xffffffff;// not supported
    }
}


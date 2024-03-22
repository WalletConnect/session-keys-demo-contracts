// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    IERC7579PermissionValidator, 
    SingleSignerPermission, ValidAfter, ValidUntil
    }  from "src/ERC7579PermissionValidator/IERC7579PermissionValidator.sol";
import "forge-std/Console2.sol";

struct PermissionSigner {
    string signerType;
    address pubKey;
}

struct PermissionObjData {
    address bakeryAddress;
    uint256 donutsLimit;
}

struct PermissionObj {
    string permType;
    PermissionObjData permObjData;
    bool required;
}

struct DonutPermissionRequest {
    PermissionSigner signer;
    PermissionObj[] permissionObjs;
}

contract DemoPermissionContextBuilder {

    function getPermissionContext(
        DonutPermissionRequest calldata donutRequest,
        address permissionValidator,
        address secp256k1Algo,
        bytes memory permissionEnableSignature
    ) public returns (bytes memory) {

        uint48 validUntil = uint48(1742573669);
        uint48 validAfter = uint48(1);

        // sig validation algo
        bytes memory signer = abi.encodePacked(donutRequest.signer.pubKey);

        // Policy
        address policyAddress = address(0xa11ce);
        bytes memory policyData = abi.encodePacked(
                        donutRequest.permissionObjs[0].permObjData.bakeryAddress,
                        donutRequest.permissionObjs[0].permObjData.donutsLimit
                    );

        SingleSignerPermission memory permission = SingleSignerPermission({
            validUntil: ValidUntil.wrap(validUntil),
            validAfter: ValidAfter.wrap(validAfter),
            signatureValidationAlgorithm: secp256k1Algo, // I WILL PROVIDE
            signer: signer, // from the INPUT OBJECT
            policy: policyAddress,
            policyData: policyData
        }); 

        bytes32[] memory permissionIds = new bytes32[](1);
        permissionIds[0] = IERC7579PermissionValidator(permissionValidator).getPermissionId(permission);

        bytes memory permissionEnableData = abi.encodePacked(
            uint8(1),
            uint64(block.chainid)
        );
        
        permissionEnableData = abi.encodePacked(permissionEnableData, permissionIds);

        bytes memory x1 = abi.encode(
                    uint256(0),
                    permission,
                    permissionEnableData,// (bytes) see below
                    permissionEnableSignature //(bytes) see below
	            );

        
        bytes memory permissionContext = 
            abi.encodePacked(
                permissionValidator,
	            bytes1(0x01),
	            x1
            );
        return permissionContext;
    }
}
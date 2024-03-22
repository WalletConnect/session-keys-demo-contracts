// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7579PermissionValidator} from "src/ERC7579PermissionValidator/IERC7579PermissionValidator.sol";

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

contract demoPermissionContextBuilder {

    function getPermissionContext(DonutPermissionRequest calldata donutRequest) public {
        
    }
}
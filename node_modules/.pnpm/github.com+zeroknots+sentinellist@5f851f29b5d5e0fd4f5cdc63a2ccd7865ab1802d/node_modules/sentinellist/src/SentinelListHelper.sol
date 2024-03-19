// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import { SentinelListLib } from "./SentinelList.sol";

library SentinelListHelper {
    using SentinelListLib for SentinelListLib.SentinelList;

    function findPrevious(
        address[] memory array,
        address entry
    )
        internal
        pure
        returns (address prev)
    {
        for (uint256 i = 0; i < array.length; i++) {
            if (array[i] == entry) {
                if (i == 0) {
                    return address(0x1);
                } else {
                    return array[i - 1];
                }
            }
        }
    }
}

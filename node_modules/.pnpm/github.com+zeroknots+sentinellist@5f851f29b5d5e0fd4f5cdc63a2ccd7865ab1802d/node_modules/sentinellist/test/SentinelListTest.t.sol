// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

import { SentinelListLib } from "../src/SentinelList.sol";
import "../src/SentinelListHelper.sol";

/// @author zeroknots
contract SentinelListTest is Test {
    using SentinelListLib for SentinelListLib.SentinelList;

    SentinelListLib.SentinelList list;

    function setUp() public {
        list.init();
    }

    function testAddMany() public {
        address addr1 = makeAddr("1");
        address addr2 = makeAddr("2");
        address addr3 = makeAddr("3");
        address addr4 = makeAddr("4");
        address addr5 = makeAddr("5");
        address addr6 = makeAddr("6");
        address addr7 = makeAddr("7");
        address addr8 = makeAddr("8");

        list.push(addr2);
        list.push(addr4);
        list.push(addr7);
        list.push(addr5);
        list.push(addr1);
        list.push(addr6);
        list.push(addr3);
        list.push(addr8);

        assertTrue(list.contains(addr1));
        assertTrue(list.contains(addr2));
        assertTrue(list.contains(addr3));
        assertTrue(list.contains(addr4));
        assertTrue(list.contains(addr5));
        assertTrue(list.contains(addr6));
        assertTrue(list.contains(addr7));
        assertTrue(list.contains(addr8));

        assertFalse(list.contains(makeAddr("9")));
    }

    function testAdd() public {
        address addr1 = makeAddr("1");
        address addr2 = makeAddr("2");

        list.push(addr2);
        assertFalse(list.contains(addr1));
        assertTrue(list.contains(addr2));
    }

    function testRemove() public {
        address addr1 = makeAddr("1");
        address addr2 = makeAddr("2");
        address addr3 = makeAddr("3");
        address addr4 = makeAddr("4");

        list.push(addr1);
        list.push(addr2);
        list.push(addr3);
        list.push(addr4);

        list.pop(addr3, addr2);

        assertTrue(list.contains(addr1));
        assertFalse(list.contains(addr2));
        assertTrue(list.contains(addr3));
        assertTrue(list.contains(addr4));

        list.push(addr2);

        assertTrue(list.contains(addr1));
        assertTrue(list.contains(addr2));
        assertTrue(list.contains(addr3));
        assertTrue(list.contains(addr4));

        (address[] memory array, address next) = list.getEntriesPaginated(address(0x1), 100);

        address remove = addr4;
        address prev = SentinelListHelper.findPrevious(array, remove);
        console2.log("prev", prev);
        console2.log("should be", addr4);

        list.pop(prev, remove);
        assertFalse(list.contains(remove));

        _log(array, next);
    }

    function _log(address[] memory array, address next) internal {
        console2.log("next", next);
        for (uint256 i = 0; i < array.length; i++) {
            console2.log("array[%s]: %s", i, array[i]);
        }
    }
}

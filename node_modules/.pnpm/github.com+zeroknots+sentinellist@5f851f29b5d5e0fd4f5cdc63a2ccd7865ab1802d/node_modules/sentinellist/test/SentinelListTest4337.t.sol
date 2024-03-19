// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

import { SentinelList4337Lib } from "../src/SentinelList4337.sol";
import "../src/SentinelListHelper.sol";

/// @author kopy-kat
contract SentinelList4337Test is Test {
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;

    SentinelList4337Lib.SentinelList list;

    address account;

    function setUp() public {
        account = makeAddr("account");
        list.init({ account: account });
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

        list.push({ account: account, newEntry: addr2 });
        list.push({ account: account, newEntry: addr4 });
        list.push({ account: account, newEntry: addr7 });
        list.push({ account: account, newEntry: addr5 });
        list.push({ account: account, newEntry: addr1 });
        list.push({ account: account, newEntry: addr6 });
        list.push({ account: account, newEntry: addr3 });
        list.push({ account: account, newEntry: addr8 });

        assertTrue(list.contains({ account: account, entry: addr1 }));
        assertTrue(list.contains({ account: account, entry: addr2 }));
        assertTrue(list.contains({ account: account, entry: addr3 }));
        assertTrue(list.contains({ account: account, entry: addr4 }));
        assertTrue(list.contains({ account: account, entry: addr5 }));
        assertTrue(list.contains({ account: account, entry: addr6 }));
        assertTrue(list.contains({ account: account, entry: addr7 }));
        assertTrue(list.contains({ account: account, entry: addr8 }));

        assertFalse(list.contains({ account: account, entry: makeAddr("9") }));
    }

    function testAdd() public {
        address addr1 = makeAddr("1");
        address addr2 = makeAddr("2");

        list.push({ account: account, newEntry: addr2 });
        assertFalse(list.contains({ account: account, entry: addr1 }));
        assertTrue(list.contains({ account: account, entry: addr2 }));
    }

    function testRemove() public {
        address addr1 = makeAddr("1");
        address addr2 = makeAddr("2");
        address addr3 = makeAddr("3");
        address addr4 = makeAddr("4");

        list.push({ account: account, newEntry: addr1 });
        list.push({ account: account, newEntry: addr2 });
        list.push({ account: account, newEntry: addr3 });
        list.push({ account: account, newEntry: addr4 });

        list.pop({ account: account, prevEntry: addr3, popEntry: addr2 });

        assertTrue(list.contains({ account: account, entry: addr1 }));
        assertFalse(list.contains({ account: account, entry: addr2 }));
        assertTrue(list.contains({ account: account, entry: addr3 }));
        assertTrue(list.contains({ account: account, entry: addr4 }));

        list.push({ account: account, newEntry: addr2 });

        assertTrue(list.contains({ account: account, entry: addr1 }));
        assertTrue(list.contains({ account: account, entry: addr2 }));
        assertTrue(list.contains({ account: account, entry: addr3 }));
        assertTrue(list.contains({ account: account, entry: addr4 }));

        (address[] memory array, address next) =
            list.getEntriesPaginated({ account: account, start: address(0x1), pageSize: 100 });

        address remove = addr4;
        address prev = SentinelListHelper.findPrevious(array, remove);
        console2.log("prev", prev);
        console2.log("should be", addr4);

        list.pop({ account: account, prevEntry: prev, popEntry: remove });
        assertFalse(list.contains({ account: account, entry: remove }));

        _log(array, next);
    }

    function _log(address[] memory array, address next) internal {
        console2.log("next", next);
        for (uint256 i = 0; i < array.length; i++) {
            console2.log("array[%s]: %s", i, array[i]);
        }
    }
}

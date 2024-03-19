// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

address constant SENTINEL = address(0x1);
address constant ZERO_ADDRESS = address(0x0);

/**
 * Implements a linked list, but adheres to ERC-4337 storage restrictions.
 * Intended use: validator modules for modular ERC-4337 smart accounts
 * @author kopy-kat | rhinestone.wtf
 */
library SentinelList4337Lib {
    struct SentinelList {
        mapping(address key => mapping(address account => address entry)) entries;
    }

    error LinkedList_AlreadyInitialized();
    error LinkedList_InvalidPage();
    error LinkedList_InvalidEntry(address entry);
    error LinkedList_EntryAlreadyInList(address entry);

    function init(SentinelList storage self, address account) internal {
        if (alreadyInitialized(self, account)) revert LinkedList_AlreadyInitialized();
        self.entries[SENTINEL][account] = SENTINEL;
    }

    function alreadyInitialized(
        SentinelList storage self,
        address account
    )
        internal
        view
        returns (bool)
    {
        return self.entries[SENTINEL][account] != ZERO_ADDRESS;
    }

    function getNext(
        SentinelList storage self,
        address account,
        address entry
    )
        internal
        view
        returns (address)
    {
        if (entry == ZERO_ADDRESS) {
            revert LinkedList_InvalidEntry(entry);
        }
        return self.entries[entry][account];
    }

    function push(SentinelList storage self, address account, address newEntry) internal {
        if (newEntry == ZERO_ADDRESS || newEntry == SENTINEL) {
            revert LinkedList_InvalidEntry(newEntry);
        }
        if (self.entries[newEntry][account] != ZERO_ADDRESS) {
            revert LinkedList_EntryAlreadyInList(newEntry);
        }
        self.entries[newEntry][account] = self.entries[SENTINEL][account];
        self.entries[SENTINEL][account] = newEntry;
    }

    function pop(
        SentinelList storage self,
        address account,
        address prevEntry,
        address popEntry
    )
        internal
    {
        if (popEntry == ZERO_ADDRESS || popEntry == SENTINEL) {
            revert LinkedList_InvalidEntry(prevEntry);
        }
        if (self.entries[prevEntry][account] != popEntry) {
            revert LinkedList_InvalidEntry(popEntry);
        }
        self.entries[prevEntry][account] = self.entries[popEntry][account];
        self.entries[popEntry][account] = ZERO_ADDRESS;
    }

    function contains(
        SentinelList storage self,
        address account,
        address entry
    )
        internal
        view
        returns (bool)
    {
        return SENTINEL != entry && self.entries[entry][account] != ZERO_ADDRESS;
    }

    function getEntriesPaginated(
        SentinelList storage self,
        address account,
        address start,
        uint256 pageSize
    )
        internal
        view
        returns (address[] memory array, address next)
    {
        if (start != SENTINEL && contains(self, account, start)) {
            revert LinkedList_InvalidEntry(start);
        }
        if (pageSize == 0) revert LinkedList_InvalidPage();
        // Init array with max page size
        array = new address[](pageSize);

        // Populate return array
        uint256 entryCount = 0;
        next = self.entries[start][account];
        while (next != ZERO_ADDRESS && next != SENTINEL && entryCount < pageSize) {
            array[entryCount] = next;
            next = self.entries[next][account];
            entryCount++;
        }

        /**
         * Because of the argument validation, we can assume that the loop will always iterate over the valid entry list values
         *       and the `next` variable will either be an enabled entry or a sentinel address (signalling the end).
         *
         *       If we haven't reached the end inside the loop, we need to set the next pointer to the last element of the entry array
         *       because the `next` variable (which is a entry by itself) acting as a pointer to the start of the next page is neither
         *       incSENTINELrent page, nor will it be included in the next one if you pass it as a start.
         */
        if (next != SENTINEL) {
            next = array[entryCount - 1];
        }
        // Set correct size of returned array
        // solhint-disable-next-line no-inline-assembly
        /// @solidity memory-safe-assembly
        assembly {
            mstore(array, entryCount)
        }
    }
}

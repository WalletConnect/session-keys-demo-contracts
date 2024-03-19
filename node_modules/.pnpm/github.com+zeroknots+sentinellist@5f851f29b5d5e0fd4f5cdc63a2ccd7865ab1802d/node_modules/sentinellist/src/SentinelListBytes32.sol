// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

bytes32 constant SENTINEL = bytes32(uint256(1));
bytes32 constant ZERO = bytes32(0x0);

library LinkedBytes32Lib {
    struct LinkedBytes32 {
        mapping(bytes32 => bytes32) entries;
    }

    error LinkedList_AlreadyInitialized();
    error LinkedList_InvalidPage();
    error LinkedList_InvalidEntry(bytes32 entry);
    error LinkedList_EntryAlreadyInList(bytes32 entry);

    function init(LinkedBytes32 storage self) internal {
        if (alreadyInitialized(self)) revert LinkedList_AlreadyInitialized();
        self.entries[SENTINEL] = SENTINEL;
    }

    function alreadyInitialized(LinkedBytes32 storage self) internal view returns (bool) {
        return self.entries[SENTINEL] != ZERO;
    }

    function getNext(LinkedBytes32 storage self, bytes32 entry) internal view returns (bytes32) {
        if (entry == ZERO) {
            revert LinkedList_InvalidEntry(entry);
        }
        return self.entries[entry];
    }

    function push(LinkedBytes32 storage self, bytes32 newEntry) internal {
        if (newEntry == ZERO || newEntry == SENTINEL) {
            revert LinkedList_InvalidEntry(newEntry);
        }
        if (self.entries[newEntry] != ZERO) revert LinkedList_EntryAlreadyInList(newEntry);
        self.entries[newEntry] = self.entries[SENTINEL];
        self.entries[SENTINEL] = newEntry;
    }

    function pop(LinkedBytes32 storage self, bytes32 prevEntry, bytes32 popEntry) internal {
        if (popEntry == ZERO || popEntry == SENTINEL) {
            revert LinkedList_InvalidEntry(prevEntry);
        }
        if (self.entries[prevEntry] != popEntry) revert LinkedList_InvalidEntry(popEntry);
        self.entries[prevEntry] = self.entries[popEntry];
        self.entries[popEntry] = ZERO;
    }

    function contains(LinkedBytes32 storage self, bytes32 entry) internal view returns (bool) {
        return SENTINEL != entry && self.entries[entry] != ZERO;
    }

    function getEntriesPaginated(
        LinkedBytes32 storage self,
        bytes32 start,
        uint256 pageSize
    )
        internal
        view
        returns (bytes32[] memory array, bytes32 next)
    {
        if (start != SENTINEL && contains(self, start)) revert LinkedList_InvalidEntry(start);
        if (pageSize == 0) revert LinkedList_InvalidPage();
        // Init array with max page size
        array = new bytes32[](pageSize);

        // Populate return array
        uint256 entryCount = 0;
        next = self.entries[start];
        while (next != ZERO && next != SENTINEL && entryCount < pageSize) {
            array[entryCount] = next;
            next = self.entries[next];
            entryCount++;
        }

        /**
         * Because of the argument validation, we can assume that the loop will always iterate over the valid entry list values
         *       and the `next` variable will either be an enabled entry or a sentinel bytes32 (signalling the end).
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

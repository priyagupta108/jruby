package org.jruby.hash;

import org.jruby.RubyString;
import org.jruby.runtime.builtin.IRubyObject;

import java.util.Arrays;

class AddressedHashStrategy implements HashStrategy {
    private static int A = 5;
    private static int C = 1;
    final static int EMPTY_BIN = -1;
    final static int DELETED_BIN = -2;
    
    @Override
    public IRubyObject put(HashImpl self, IRubyObject key, int hash, IRubyObject value) {
        int bin;
        IRubyObject result;

        bin = internalGetBinOpenAddressing(self, hash, key);
        result = internalSetValueByBin(self, bin, value);
        if (result != null) return result;
        internalPutOpenAdressing(self, hash, bin, key, value);

        // no existing entry
        return null;
    }

    @Override
    public void putDirect(HashImpl self, IRubyObject key, int hash, IRubyObject value) {
        internalPutOpenAdressing(self, hash, EMPTY_BIN, key, value);
    }

    @Override
    public IRubyObject get(HashImpl self, IRubyObject key, int hash) {
        final int bin = internalGetBinOpenAddressing(self, hash, key);
        if (bin < 0) return null;
        int index = self.bins[bin];
        return internalGetValue(self, index);
    }

    @Override
    public void putString(HashImpl self, RubyString key, int hash, IRubyObject value) {
        int[] bins = self.bins;
        final int oldBinsLength = bins.length;
        int bin = internalGetBinOpenAddressing(self, hash, key);
        if (internalSetValueByBin(self, bin, value) != null) return;

        if (!key.isFrozen()) key = (RubyString)key.dupFrozen();
        self.checkResize();
        // we need to calculate the bin again if we changed the size
        if (bins.length != oldBinsLength)
            bin = internalGetBinOpenAddressing(self, hash, key);
        internalPutOpenAdressing(self, hash, bin, key, value);
    }

    @Override
    public void rehash(HashImpl self) {
        rehashOpenAddressing(self);
    }

    @Override
    public IRubyObject delete(HashImpl self, HashImpl.EntryMatchType matchType, IRubyObject key, int hash, IRubyObject value) {
        return internalDeleteOpenAddressing(self, hash, matchType, key, value);
    }

    @Override
    public void copy(HashImpl self, HashImpl target) {
        target.entries = self.internalCopyTable();
        target.bins = internalCopyBins(self);
        target.hashes = self.internalCopyHashes();
        target.size = self.size;
        target.extents = self.extents;
        target.strategy = this;
    }

    @Override
    public void alloc(HashImpl self, int buckets) {
        int nextPowOfTwo = HashImpl.nextPowOfTwo(buckets);
        self.entries = new IRubyObject[nextPowOfTwo << 1];
        self.bins = new int[nextPowOfTwo << 1];
        self.hashes = new int[nextPowOfTwo];
        Arrays.fill(self.bins, EMPTY_BIN);
    }

    @Override
    public void resize(HashImpl self, int newCapacity) {
        final IRubyObject[] newEntries = new IRubyObject[newCapacity << 1];
        final int[] newBins = new int[newCapacity << 1];
        final int[] newHashes = new int[newCapacity];
        Arrays.fill(newBins, EMPTY_BIN);

        IRubyObject[] entries = self.entries;
        int[] hashes = self.hashes;

        System.arraycopy(entries, 0, newEntries, 0, entries.length);
        System.arraycopy(hashes, 0, newHashes, 0, hashes.length);

        long startEnd = self.extents;
        int start = HashImpl.START(startEnd);
        int end = HashImpl.END(startEnd);

        for (int i = start; i < end; i++) {
            if (HashImpl.entryKey(entries, i) == null) continue;

            int bin = bucketIndex(hashes[i], newBins.length);
            int index = newBins[bin];
            while(index != EMPTY_BIN) {
                bin = secondaryBucketIndex(bin, newBins.length);
                index = newBins[bin];
            }
            newBins[bin] = i;
        }

        self.bins = newBins;
        self.hashes = newHashes;
        self.entries = newEntries;
    }

    private static int bucketIndex(final int h, final int length) {
        // binary AND ($NUMBER - 1) is the same as MODULO
        return h & (length - 1);
    }

    private static int secondaryBucketIndex(final int bucketIndex, final int length) {
        return (A * bucketIndex + C) & (length - 1);
    }

    private final int internalGetBinOpenAddressing(HashImpl self, final int hash, final IRubyObject key) {
        int[] bins = self.bins;

        int bin = bucketIndex(hash, bins.length);
        int index = bins[bin];

        IRubyObject[] entries = self.entries;
        int[] hashes = self.hashes;

        for (int round = 0; round < bins.length && index != EMPTY_BIN; round++) {
            if (round == bins.length) break;

            if (index != DELETED_BIN) {
                IRubyObject otherKey = HashImpl.entryKey(entries, index);
                int otherHash = hashes[index];

                if (HashImpl.internalKeyExist(key, hash, otherKey, otherHash, self.isComparedByIdentity())) return bin;
            }

            bin = secondaryBucketIndex(bin, bins.length);
            index = bins[bin];
        }

        return EMPTY_BIN;
    }

    private final IRubyObject internalSetValueByBin(HashImpl self, final int bin, final IRubyObject value) {
        if (bin < 0) return null;
        int index = self.bins[bin];
        return internalSetValue(self, index, value);
    }

    private final IRubyObject internalPutOpenAdressing(HashImpl self, final int hash, int bin, final IRubyObject key, final IRubyObject value) {
        self.checkIterating();

        int[] bins = self.bins;

        int localBin = (bin == EMPTY_BIN) ? bucketIndex(hash, bins.length) : bin;
        int index = bins[localBin];

        int end = self.getEnd();
        IRubyObject[] entries = self.entries;

        HashImpl.set(entries, end, key, value);

        while(index != EMPTY_BIN && index != DELETED_BIN) {
            localBin = secondaryBucketIndex(localBin, bins.length);
            index = bins[localBin];
        }

        bins[localBin] = end;
        self.hashes[end] = hash;

        self.size++;
        self.setEnd(end + 1);

        // no existing entry
        return null;
    }

    private final IRubyObject internalSetValue(HashImpl self, final int index, final IRubyObject value) {
        if (index < 0) return null;

        IRubyObject[] entries = self.entries;

        final IRubyObject result = HashImpl.entryValue(entries, index);
        HashImpl.entryValue(entries, index, value);

        return result;
    }

    private final IRubyObject internalGetValue(HashImpl self, final int index) {
        if (index < 0) return null;
        return HashImpl.entryValue(self.entries, index);
    }

    private void rehashOpenAddressing(HashImpl self) {
        IRubyObject[] entries = self.entries;

        IRubyObject[] newEntries = new IRubyObject[entries.length];
        int[] bins = self.bins;

        int[] hashes = self.hashes;

        int[] newBins = new int[bins.length];
        int[] newHashes = new int[hashes.length];
        Arrays.fill(newBins, EMPTY_BIN);

        int newIndex = 0;
        long extents = self.extents;
        int start = HashImpl.START(extents);
        int end = HashImpl.END(extents);

        for(int i = start; i < end; i++) {
            IRubyObject key = HashImpl.entryKey(entries, i);
            if (key == null) continue;

            int hash = self.hashValue(key);
            int bin = bucketIndex(hash, newBins.length);
            int index = newBins[bin];

            boolean exists = false;
            while(index != EMPTY_BIN) {
                // Note: otherKey should never be null here as we are filling with new entries and newBins
                // cannot be non-EMPTY_BIN and not contain a valid newEntry.
                IRubyObject otherKey = HashImpl.entryKey(newEntries, index);
                int otherHash = newHashes[index];
                if (HashImpl.internalKeyExist(key, hash, otherKey, otherHash, self.isComparedByIdentity())) {
                    // exists, we do not need to add this key
                    exists = true;
                    break;
                }

                bin = secondaryBucketIndex(bin, newBins.length);
                index = newBins[bin];
            }

            if (!exists) {
                newBins[bin] = newIndex;
                HashImpl.set(newEntries, newIndex, key, HashImpl.entryValue(entries, i));
                newHashes[newIndex] = hash;
                newIndex++;
            }
        }

        self.bins = newBins;
        self.entries = newEntries;
        self.hashes = newHashes;
        self.setExtents(0, self.size = newIndex);
    }

    private final IRubyObject internalDeleteOpenAddressing(HashImpl self, final int hash, final HashImpl.EntryMatchType matchType, final IRubyObject key, final IRubyObject value) {
        int[] bins = self.bins;

        int bin = bucketIndex(hash, bins.length);
        int index = bins[bin];

        IRubyObject[] entries = self.entries;
        int[] hashes = self.hashes;

        for (int round = 0; round < bins.length && index != EMPTY_BIN; round++) {
            if (index != DELETED_BIN) {
                IRubyObject otherKey = HashImpl.entryKey(entries, index);
                IRubyObject otherValue = HashImpl.entryValue(entries, index);

                if (otherKey != null && matchType.matches(key, value, otherKey, otherValue)) {
                    bins[bin] = DELETED_BIN;
                    hashes[index] = 0;
                    HashImpl.unset(entries, index);
                    self.size--;

                    self.updateStartAndEndPointer();
                    return otherValue;
                }
            }
            bin = secondaryBucketIndex(bin, bins.length);
            index = bins[bin];
        }

        return null;  // no entry found
    }

    private final int[] internalCopyBins(HashImpl self) {
        int[] bins = self.bins;
        int[] newBins = new int[bins.length];
        System.arraycopy(bins, 0, newBins, 0, bins.length);
        return newBins;
    }

}

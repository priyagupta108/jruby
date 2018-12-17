package org.jruby;

import org.jruby.runtime.builtin.IRubyObject;

import java.util.Arrays;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.function.ToIntFunction;

class HashStateWithBins<Base, Key extends Base, Value extends Base> extends HashState<Base, Key, Value> {
    HashStateWithBins(HashState<Base, Key, Value> state, Base[] entries, int[] hashes, int[] bins) {
        super(state, entries, hashes);
        this.bins = bins;
    }

    HashStateWithBins(RubyHash rubyHash, ToIntFunction<Key> hash, BiPredicate<Key, Key> keyEqual, ObjectIntObjectIntPredicate<Key, Key> exist, int buckets) {
        super(rubyHash, hash, keyEqual, exist, 0, 0, 0, 0, buckets);
        int[] bins = new int[nextPowOfTwo(buckets) << 1];
        this.bins = bins;
        Arrays.fill(bins, EMPTY_BIN);
    }

    HashStateWithBins(HashStateWithBins state) {
        super(state);
        this.bins = state.internalCopyBins();
    }

    @Override
    public HashStateWithBins clone() {
        return new HashStateWithBins(this);
    }

    void clear() {
        if (size > 0) {
            super.clear();
            int nextPowOfTwo = nextPowOfTwo(MRI_INITIAL_CAPACITY);
            int[] bins = new int[nextPowOfTwo << 1];
            this.bins = bins;
        }
    }

    protected Value internalPut(Key key, Value value, int hash) {
        int bin;
        Value result;
        bin = internalGetBinOpenAddressing(hash, key);
        result = internalSetValueByBin(bin, value);
        if (result != null) return result;
        internalPutOpenAdressing(hash, bin, key, value);
        return null;
    }

    @Override
    protected Value internalGet(Key key, int hash) {
        final int bin = internalGetBinOpenAddressing(hash, key);
        if (bin < 0) return null;
        return internalGetValue(bins[bin]);
    }

    @Override
    protected Value internalDelete(final EntryMatchType<Key, Value> matchType, final Key key, final Value value) {
        int hash = this.hash.applyAsInt(key);
        int[] bins = this.bins;

        int bin = bucketIndex(hash, bins.length);
        int index = bins[bin];

        Base[] entries = this.entries;
        int[] hashes = this.hashes;

        for (int round = 0; round < bins.length && index != EMPTY_BIN; round++) {
            if (index != RubyHash.DELETED_BIN) {
                Key otherKey = entryKey(entries, index);
                Value otherValue = entryValue(entries, index);

                if (otherKey != null && matchType.matches(key, value, otherKey, otherValue)) {
                    bins[bin] = RubyHash.DELETED_BIN;
                    hashes[index] = 0;
                    unset(entries, index);
                    size--;

                    updateStartAndEndPointer();
                    return otherValue;
                }
            }
            bin = secondaryBucketIndex(bin, bins.length);
            index = bins[bin];
        }

        return null;  // no entry found
    }

    @Override
    public void rehash() {
        Base[] entries = this.entries;

        Base[] newEntries = (Base[]) new Object[entries.length];
        int[] bins = this.bins;

        int[] hashes = this.hashes;

        int[] newBins = new int[bins.length];
        int[] newHashes = new int[hashes.length];
        Arrays.fill(newBins, EMPTY_BIN);

        int newIndex = 0;

        int start = this.start;
        int end = this.end;

        for(int i = start; i < end; i++) {
            Key key = entryKey(entries, i);
            if (key == null) continue;

            int hash = this.hash.applyAsInt(key);
            int bin = bucketIndex(hash, newBins.length);
            int index = newBins[bin];

            boolean exists = false;
            while(index != EMPTY_BIN) {
                // Note: otherKey should never be null here as we are filling with new entries and newBins
                // cannot be non-EMPTY_BIN and not contain a valid newEntry.
                Key otherKey = entryKey(newEntries, index);
                int otherHash = newHashes[index];
                if (exist.test(key, hash, otherKey, otherHash)) {
                    // exists, we do not need to add this key
                    exists = true;
                    break;
                }

                bin = secondaryBucketIndex(bin, newBins.length);
                index = newBins[bin];
            }

            if (!exists) {
                newBins[bin] = newIndex;
                set(newEntries, newIndex, key, entryValue(entries, i));
                newHashes[newIndex] = hash;
                newIndex++;
            }
        }

        this.bins = newBins;
        this.entries = newEntries;
        this.hashes = newHashes;
        this.setExtents(0, size = newIndex);
    }

    @Override
    protected <KeySub extends Key> void putTranslated(KeySub key, Value value, Function<KeySub, Key> keyTranslate) {
        int[] bins = this.bins;
        final int oldBinsLength = bins.length;
        int hash = this.hash.applyAsInt(key);
        int bin = internalGetBinOpenAddressing(hash, key);
        if (internalSetValueByBin(bin, value) != null) return;

        Key key2 = keyTranslate.apply(key);
        checkResize();
        // we need to calculate the bin again if we changed the size
        if (bins.length != oldBinsLength)
            bin = internalGetBinOpenAddressing(hash, key2);
        internalPutOpenAdressing(hash, bin, key2, value);
    }

    private final IRubyObject internalPutOpenAdressing(final int hash, int bin, final Key key, final Value value) {
        checkIterating();

        int[] bins = this.bins;

        int localBin = (bin == EMPTY_BIN) ? bucketIndex(hash, bins.length) : bin;
        int index = bins[localBin];

        int end = getEnd();
        Base[] entries = this.entries;

        set(entries, end, key, value);

        while(index != EMPTY_BIN && index != RubyHash.DELETED_BIN) {
            localBin = secondaryBucketIndex(localBin, bins.length);
            index = bins[localBin];
        }

        bins[localBin] = end;
        hashes[end] = hash;

        size++;
        setEnd(end + 1);

        // no existing entry
        return null;
    }

    private final int internalGetBinOpenAddressing(final int hash, final Key key) {
        int[] bins = this.bins;

        int bin = bucketIndex(hash, bins.length);
        int index = bins[bin];

        Base[] entries = this.entries;
        int[] hashes = this.hashes;

        for (int round = 0; round < bins.length && index != EMPTY_BIN; round++) {
            if (round == bins.length) break;

            if (index != RubyHash.DELETED_BIN) {
                Key otherKey = entryKey(entries, index);
                int otherHash = hashes[index];

                if (exist.test(key, hash, otherKey, otherHash)) return bin;
            }

            bin = secondaryBucketIndex(bin, bins.length);
            index = bins[bin];
        }

        return EMPTY_BIN;
    }

    private final Value internalSetValueByBin(final int bin, final Value value) {
        if (bin < 0) return null;
        int index = bins[bin];
        return internalSetValue(index, value);
    }

    private final int[] internalCopyBins() {
        int[] bins = this.bins;
        int[] newBins = new int[bins.length];
        System.arraycopy(bins, 0, newBins, 0, bins.length);
        return newBins;
    }

    private int[] bins;
}

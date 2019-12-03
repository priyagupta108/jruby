package org.jruby.hash;

import org.jruby.RubyString;
import org.jruby.runtime.builtin.IRubyObject;

class LinearHashStrategy implements HashStrategy {
    @Override
    public IRubyObject put(HashImpl self, IRubyObject key, int hash, IRubyObject value) {
        int index;
        IRubyObject result;

        index = internalGetIndexLinearSearch(self, hash, key);
        result = internalSetValue(self, index, value);
        if (result != null) return result;
        internalPutLinearSearch(self, hash, key, value);

        // no existing entry
        return null;
    }

    @Override
    public void putDirect(HashImpl self, IRubyObject key, int hash, IRubyObject value) {
        internalPutLinearSearch(self, hash, key, value);
    }

    @Override
    public IRubyObject get(HashImpl self, IRubyObject key, int hash) {
        int index = internalGetIndexLinearSearch(self, hash, key);
        return internalGetValue(self, index);
    }

    @Override
    public void putString(HashImpl self, RubyString key, int hash, IRubyObject value) {
        final int index = internalGetIndexLinearSearch(self, hash, key);
        if (internalSetValue(self, index, value) != null) return;
        if (!key.isFrozen()) key = (RubyString)key.dupFrozen();
        self.checkResize();

        // It could be that we changed from linear search to open addressing with the resize
        self.strategy.putDirect(self, key, hash, value);

        return;
    }

    @Override
    public void rehash(HashImpl self) {
        rehashLinearSearch(self);
    }

    @Override
    public IRubyObject delete(HashImpl self, HashImpl.EntryMatchType matchType, IRubyObject key, int hash, IRubyObject value) {
        return internalDeleteLinearSearch(self, matchType, key, value);
    }

    @Override
    public void copy(HashImpl self, HashImpl target) {
        target.entries = self.internalCopyTable();
        target.bins = null;
        target.hashes = self.internalCopyHashes();
        target.size = self.size;
        target.extents = self.extents;
        target.strategy = this;
    }

    @Override
    public void alloc(HashImpl self, int buckets) {
        allocFirst(self);
    }

    @Override
    public void resize(HashImpl self, int newCapacity) {
        // resize always switches to addressed
        self.strategy = HashImpl.ADDRESSED;

        HashImpl.ADDRESSED.resize(self, newCapacity);
    }

    private final int internalGetIndexLinearSearch(HashImpl self, final int hash, final IRubyObject key) {
        long extents = self.extents;
        int start = HashImpl.START(extents);
        int end = HashImpl.END(extents);
        IRubyObject[] entries = self.entries;
        int[] hashes = self.hashes;

        for(int i = start; i < end; i++) {
            IRubyObject otherKey = HashImpl.entryKey(entries, i);
            if (otherKey == null) continue;

            int otherHash = hashes[i];

            if (HashImpl.internalKeyExist(key, hash, otherKey, otherHash, self.isComparedByIdentity())) return i;
        }
        return -1;
    }

    private final IRubyObject internalSetValue(HashImpl self, final int index, final IRubyObject value) {
        if (index < 0) return null;

        IRubyObject[] entries = self.entries;

        final IRubyObject result = HashImpl.entryValue(entries, index);
        HashImpl.entryValue(entries, index, value);

        return result;
    }

    private final IRubyObject internalPutLinearSearch(HashImpl self, final int hash, final IRubyObject key, final IRubyObject value) {
        self.checkIterating();

        int end = self.getEnd();
        IRubyObject[] entries = self.entries;

        HashImpl.set(entries, end, key, value);

        self.hashes[end] = hash;

        self.size++;
        self.setEnd(end + 1);

        // no existing entry
        return null;
    }

    private final IRubyObject internalGetValue(HashImpl self, final int index) {
        if (index < 0) return null;
        return HashImpl.entryValue(self.entries, index);
    }

    private void rehashLinearSearch(HashImpl self) {
        IRubyObject[] entries = self.entries;
        int[] hashes = self.hashes;

        IRubyObject[] newEntries = new IRubyObject[entries.length];
        int[] newHashes = new int[hashes.length];
        int newIndex = 0;

        long extents = self.extents;
        int start = HashImpl.START(extents);
        int end = HashImpl.END(extents);

        for(int i = start; i < end; i++) {
            IRubyObject key = HashImpl.entryKey(entries, i);
            if (key == null) continue;

            int newHash = self.hashValue(key);
            boolean exists = false;
            for(int j = 0; j < i; j++) {
                int otherHash = hashes[j];
                IRubyObject otherKey = HashImpl.entryKey(newEntries, j);
                if (HashImpl.internalKeyExist(key, newHash, otherKey, otherHash, self.isComparedByIdentity())) {
                    exists = true;
                    break;
                }
            }

            if (!exists) {
                HashImpl.set(newEntries, newIndex, key, HashImpl.entryValue(entries, i));
                newHashes[newIndex] = newHash;
                newIndex++;
            }
        }

        self.entries = newEntries;
        self.hashes = newHashes;
        self.setExtents(0, self.size = newIndex);
    }

    private final IRubyObject internalDeleteLinearSearch(HashImpl self, final HashImpl.EntryMatchType matchType, final IRubyObject key, final IRubyObject value) {
        long extents = self.extents;
        int start = HashImpl.START(extents);
        int end = HashImpl.END(extents);
        IRubyObject[] entries = self.entries;
        int[] hashes = self.hashes;

        for(int index = start; index < end; index++) {
            IRubyObject otherKey = HashImpl.entryKey(entries, index);
            IRubyObject otherValue = HashImpl.entryValue(entries, index);

            if (otherKey == null) continue;

            if (matchType.matches(key, value, otherKey, otherValue)) {
                hashes[index] = 0;
                HashImpl.unset(entries, index);
                self.size--;

                self.updateStartAndEndPointer();
                return otherValue;
            }
        }

        // no entry
        return null;
    }

    private final void allocFirst(HashImpl self) {
        self.entries = new IRubyObject[HashImpl.MRI_INITIAL_CAPACITY << 1];
        self.hashes = new int[HashImpl.MRI_INITIAL_CAPACITY];
    }
}

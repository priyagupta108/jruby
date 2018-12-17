package org.jruby;

import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.function.BiPredicate;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.ToIntFunction;

class HashState<Base, Key extends Base, Value extends Base> {
    HashState(RubyHash rubyHash, ToIntFunction<Key> hash, BiPredicate<Key, Key> keyEqual, ObjectIntObjectIntPredicate<Key, Key> exist, int size, int generation, int start, int end, Base[] entries, int[] hashes) {
        this.rubyHash = rubyHash;
        this.size = size;
        this.generation = generation;
        this.start = start;
        this.end = end;
        this.entries = entries;
        this.hashes = hashes;
        this.hash = hash;
        this.keyEqual = keyEqual;
        this.exist = exist;
    }

    HashState(RubyHash rubyHash, ToIntFunction<Key> hash, BiPredicate<Key, Key> keyEqual, ObjectIntObjectIntPredicate<Key, Key> exist, int size, int generation, int start, int end, int buckets) {
        this.rubyHash = rubyHash;
        this.size = size;
        this.generation = generation;
        this.start = start;
        this.end = end;
        int nextPowOfTwo = nextPowOfTwo(buckets);
        this.entries = (Base[]) new Object[nextPowOfTwo << 1];
        this.hashes = new int[nextPowOfTwo];
        this.hash = hash;
        this.keyEqual = keyEqual;
        this.exist = exist;
    }

    HashState(RubyHash rubyHash, ToIntFunction<Key> hash, BiPredicate<Key, Key> keyEqual, ObjectIntObjectIntPredicate<Key, Key> exist) {
        this(rubyHash, hash, keyEqual, exist, 0, 0, 0, 0, MRI_INITIAL_CAPACITY);
    }

    HashState(HashState<Base, Key, Value> state) {
        this(
                state.rubyHash,
                state.hash,
                state.keyEqual,
                state.exist,
                state.size,
                state.generation,
                state.start,
                state.end,
                state.internalCopyTable(),
                state.internalCopyHashes());
    }

    HashState(HashState state, Base[] entries, int[] hashes) {
        this(
                state.rubyHash,
                state.hash,
                state.keyEqual,
                state.exist,
                state.size,
                state.generation,
                state.start,
                state.end,
                entries,
                hashes);
    }

    static final int MRI_INITIAL_CAPACITY = 8;

    boolean allKeysMatch(Predicate<Key> test) {
        int startGeneration = generation;
        int start = this.start;
        int end = this.end;
        Base[] entries = this.entries;
        for (int i = start; i < end; i++) {
            int currentGeneration = generation;
            if (startGeneration != currentGeneration) {
                startGeneration = currentGeneration;
                i = start;
            }
            Key key = entryKey(entries, i);
            if (key != null && test.test(key)) return false;
        }
        return true;

    }

    protected interface EntryMatchType<Key, Value> {
        boolean matches(final Key key, final Value value, final Key otherKey, final Value otherValue);
    }

    protected static int nextPowOfTwo(final int i) {
        return Integer.MIN_VALUE >>> Integer.numberOfLeadingZeros(i - 1) << 1; // i > 1
    }

    public HashState clone() {
        return new HashState(this);
    }

    <S> boolean any(S state, RubyHash.TriPredicate<S, Key, Value> yielder) {
        iteratorEntry();
        try {
            int start = this.start;
            int end = this.end;
            Base[] entries = this.entries;

            for (int i = start; i < end; i++) {
                Key key = entryKey(entries, i);
                Value value = entryValue(entries, i);

                if (key == null || value == null) continue;

                if (yielder.test(state, key, value)) return true;
            }
            return true;
        } finally {
            iteratorExit();
        }
    }
    private static final int NUMBER_OF_ENTRIES = 2;

    protected Key entryKey(Base[] entries, int index) {
        return (Key) entries[index * NUMBER_OF_ENTRIES];
    }

    protected Value entryValue(Base[] entries, int index) {
        return (Value) entries[index * NUMBER_OF_ENTRIES + 1];
    }

    private static <B, V extends B> B entryValue(B[] entries, int index, V value) {
        return entries[index * NUMBER_OF_ENTRIES + 1] = value;
    }

    protected void set(Base[] entries, int index, Key key, Value value) {
        entries[index * NUMBER_OF_ENTRIES] = key;
        entries[index * NUMBER_OF_ENTRIES + 1] = value;
    }

    protected void unset(Base[] entries, int index) {
        set(entries, index, null, null);
    }

    boolean compact(ThreadContext context) {
        boolean changed = false;
        iteratorEntry();
        try {
            Key key;
            Value value;

            int start = this.start;
            int end = this.end;
            Base[] entries = this.entries;

            for (int i = start; i < end; i++) {
                value = entryValue(entries, i);
                if (value == context.nil) {
                    key = entryKey(entries, i);
                    internalDelete(key);
                    changed = true;
                }
            }
        } finally {
            iteratorExit();
        }
        return changed;
    }

    void clear() {
        if (size > 0) {
            int nextPowOfTwo = nextPowOfTwo(MRI_INITIAL_CAPACITY);
            this.entries = (Base[]) new Object[nextPowOfTwo << 1];
            this.hashes = new int[nextPowOfTwo];
            start = end = size = 0;
        }
    }

    <S, R> R shift(S state, RubyHash.TriFunction<S, Key, Value, R> result) {
        int start = this.start;
        int end = this.end;

        Base[] entries = this.entries;
        Key key = entryKey(entries, start);
        Value value = entryValue(entries, start);

        if (getLength() == end || key != entryKey(entries, end)) {
            internalDelete(key);
            return result.apply(state, key, value);
        }

        return null;
    }

    <State, T> void visitLimited(State context, RubyHash.HashVisitor<State, Key, Value, T> visitor, long size, T state) {
        int startGeneration = generation;
        long count = size;
        int index = 0;

        Base[] entries = this.entries;

        int start = this.start;
        int end = this.end;
        for (int i = start; i < end && count != 0; i++) {
            if (startGeneration != generation) {
                startGeneration = generation;
                i = start;
            }

            Key key = entryKey(entries, i);
            Value value = entryValue(entries, i);

            if(key == null || value == null) continue;

            visitor.visit(context, rubyHash, key, value, index++, state);
            count--;
        }

        // it does not handle all concurrent modification cases,
        // but at least provides correct marshal as we have exactly size entries visited (count == 0)
        // or if count < 0 - skipped concurrent modification checks
        if (count > 0) throw rubyHash.concurrentModification();
    }

    private final Base[] internalCopyTable() {
        Base[] entries = this.entries;
        Base[] newTable = (Base[]) new Object[entries.length];
        System.arraycopy(entries, 0, newTable, 0, entries.length);
        return newTable;
    }

    private final int[] internalCopyHashes() {
        int[] hashes = this.hashes;
        int[] newHashes = new int[hashes.length];
        System.arraycopy(hashes, 0, newHashes, 0, hashes.length);
        return newHashes;
    }

    private final int getLength() {
        return entries.length / NUMBER_OF_ENTRIES;
    }

    private final HashState resize(final int newCapacity) {
        final IRubyObject[] newEntries = new IRubyObject[newCapacity << 1];
        final int[] newBins = new int[newCapacity << 1];
        final int[] newHashes = new int[newCapacity];
        Arrays.fill(newBins, EMPTY_BIN);

        Base[] entries = this.entries;
        int[] hashes = this.hashes;

        System.arraycopy(entries, 0, newEntries, 0, entries.length);
        System.arraycopy(hashes, 0, newHashes, 0, hashes.length);


        int start = this.start;
        int end = this.end;

        for (int i = start; i < end; i++) {
            if (entryKey(entries, i) == null) continue;

            int bin = bucketIndex(hashes[i], newBins.length);
            int index = newBins[bin];
            while(index != EMPTY_BIN) {
                bin = secondaryBucketIndex(bin, newBins.length);
                index = newBins[bin];
            }
            newBins[bin] = i;
        }

        return new HashStateWithBins(this, newEntries, newHashes, newBins);
    }

    protected static final int EMPTY_BIN = -1;
    private static final int A = 5;
    private static final int C = 1;

    protected static int bucketIndex(final int h, final int length) {
        // binary AND ($NUMBER - 1) is the same as MODULO
        return h & (length - 1);
    }

    protected static int secondaryBucketIndex(final int bucketIndex, final int length) {
        return (A * bucketIndex + C) & (length - 1);
    }

    protected HashState checkResize() {
        if (getLength() == end) {
            return resize(entries.length << 2);
        }
        return this;
    }

    protected Value put(Key key, Value value) {
        checkResize();

        return internalPut(key, value, hash.applyAsInt(key));
    }

    <KeySub extends Key> void putTranslated(KeySub key, Value value, Function<KeySub, Key> keyTranslate) {
        int hash = this.hash.applyAsInt(key);
        final int index = internalGetIndexLinearSearch(hash, key);
        if (internalSetValue(index, value) != null) return;
        Key key2 = keyTranslate.apply(key);
        checkResize();
        internalPutLinearSearch(hash, key2, value);
    }

    protected Value internalPut(final Key key, final Value value, final int hash) {
        int index = internalGetIndexLinearSearch(hash, key);
        Value result = internalSetValue(index, value);
        if (result != null) return result;
        internalPutLinearSearch(hash, key, value);

        // no existing entry
        return null;
    }

    protected int getEnd() {
        return end;
    }

    protected void setEnd(int newEnd) {
        this.end = newEnd;
    }

    private int getStart() {
        return start;
    }

    private void setStart(int newStart) {
        this.start = newStart;
    }

    private final IRubyObject internalPutLinearSearch(final int hash, final Key key, final Value value) {
        checkIterating();

        int end = getEnd();
        Base[] entries = this.entries;

        set(entries, end, key, value);

        hashes[end] = hash;

        size++;
        setEnd(end + 1);

        // no existing entry
        return null;
    }

    protected final Value internalSetValue(final int index, final Value value) {
        if (index < 0) return null;

        Base[] entries = this.entries;

        final Value result = entryValue(entries, index);
        entryValue(entries, index, value);

        return result;
    }

    // get implementation

    protected final Value internalGetValue(final int index) {
        if (index < 0) return null;
        return entryValue(entries, index);
    }

    private final int internalGetIndexLinearSearch(final int hash, final Key key) {
        int start = this.start;
        int end = this.end;
        Base[] entries = this.entries;
        int[] hashes = this.hashes;

        for(int i = start; i < end; i++) {
            Key otherKey = entryKey(entries, i);
            if (otherKey == null) continue;

            int otherHash = hashes[i];

            if (exist.test(key, hash, otherKey, otherHash)) return i;
        }
        return EMPTY_BIN;
    }

    protected Value internalGet(Key key) { // specialized for value
        if (rubyHash.isEmpty()) return null;
        return internalGet(key, hash.applyAsInt(key));
    }

    protected Value internalGet(Key key, int hash) {
        int index;
        index = internalGetIndexLinearSearch(hash, key);
        return internalGetValue(index);
    }

    // delete implementation

    protected Value internalDelete(final Key key) {
        if (size == 0) return null;
        return internalDelete(this::matchKey, key, null);
    }

    private boolean matchKey(Key key, Value value, Key oldKey, Value oldValue) {
        return keyEqual.test(key, oldKey);
    }

    protected void updateStartAndEndPointer() {
        if (rubyHash.isEmpty()) {
            start = end = 0;
        } else {
            Base[] entries = this.entries;

            int start = this.start;
            while (entryKey(entries, start) == null) {
                start++;
            }

            int end = this.end;
            while((end - 1) > 0 && entryKey(entries, end - 1) == null) {
                end--;
            }

            setExtents(start, end);
        }
    }

    protected void setExtents(int start, int end) {
        this.start = start;
        this.end = end;
    }

    private int lastElementsIndex() {
        return getEnd() - 1;
    }

    protected final void checkIterating() {
        if (iteratorCount > 0) {
            throw rubyHash.getRuntime().newRuntimeError("can't add a new key into hash during iteration");
        }
    }

    protected Value internalDelete(final EntryMatchType<Key, Value> matchType, final Key key, final Value value) {
        int hash = this.hash.applyAsInt(key);
        if (rubyHash.isEmpty()) return null;
        int start = this.start;
        int end = this.end;
        Base[] entries = this.entries;
        int[] hashes = this.hashes;

        for(int index = start; index < end; index++) {
            Key otherKey = entryKey(entries, index);
            Value otherValue = entryValue(entries, index);

            if (otherKey == null) continue;

            if (matchType.matches(key, value, otherKey, otherValue)) {
                hashes[index] = 0;
                unset(entries, index);
                size--;

                updateStartAndEndPointer();
                return otherValue;
            }
        }

        // no entry
        return null;
    }

    public void rehash() {
        Base[] entries = this.entries;
        int[] hashes = this.hashes;

        Base[] newEntries = (Base[]) new Object[entries.length];
        int[] newHashes = new int[hashes.length];
        int newIndex = 0;

        int start1 = this.start;
        int end1 = this.end;

        for(int i = start1; i < end1; i++) {
            Key key = entryKey(entries, i);
            if (key == null) continue;

            int newHash = hash.applyAsInt(key);
            boolean exists = false;
            for(int j = 0; j < i; j++) {
                int otherHash = hashes[j];
                Key otherKey = entryKey(newEntries, j);
                if (exist.test(key, newHash, otherKey, otherHash)) {
                    exists = true;
                    break;
                }
            }

            if (!exists) {
                set(newEntries, newIndex, key, entryValue(entries, i));
                newHashes[newIndex] = newHash;
                newIndex++;
            }
        }

        this.entries = newEntries;
        this.hashes = newHashes;
        this.setExtents(0, size = newIndex);
    }

    public Iterator iterator(RubyHash.EntryView view) {
        return new BaseIterator(view);
    }

    private class BaseIterator implements Iterator {
        private RubyHash.EntryView view;
        private Key key;
        private Value value;
        private boolean peeking, hasNext;
        private int startGeneration, index, end;

        public BaseIterator(RubyHash.EntryView view) {
            this.view = view;
            this.startGeneration = HashState.this.generation;
            int start = HashState.this.start;
            int end = HashState.this.end;
            this.index = start;
            this.end = end;
            this.hasNext = HashState.this.size > 0;
        }

        private void advance(boolean consume) {
            if (!peeking) {
                do {
                    Base[] entries = HashState.this.entries;
                    if (startGeneration != HashState.this.generation) {
                        startGeneration = HashState.this.generation;
                        index = getStart();
                        key = entryKey(entries, index);
                        value = entryValue(entries, index);
                        index++;
                        hasNext = HashState.this.size > 0;
                    } else {
                        if (index < end) {
                            key = entryKey(entries, index);
                            value = entryValue(entries, index);
                            index++;
                            hasNext = true;
                        } else {
                            hasNext = false;
                        }
                    }
                    while((key == null || value == null) && index < end && hasNext) {
                        key = entryKey(entries, index);
                        value = entryValue(entries, index);
                        index++;
                    }
                } while ((key == null || value == null) && index < size);
            }
            peeking = !consume;
        }

        @Override
        public Object next() {
            advance(true);
            if (!hasNext) {
                peeking = true; // remain where we are
                throw new NoSuchElementException();
            }
            return view.convertEntry(rubyHash.getRuntime(), rubyHash, key, value);
        }

        // once hasNext has been called, we commit to next() returning
        // the entry it found, even if it were subsequently deleted
        @Override
        public boolean hasNext() {
            advance(false);
            return hasNext;
        }

        @Override
        public void remove() {
            if (!hasNext) {
                throw new IllegalStateException("Iterator out of range");
            }
            internalDelete(key);
        }
    }

    private volatile int iteratorCount;

    boolean iterating(BooleanSupplier p) {
        iteratorEntry();
        try {
            return p.getAsBoolean();
        } finally {
            iteratorExit();
        }
    }

    void iteratorEntry() {
        ITERATOR_UPDATER.incrementAndGet(this);
    }

    void iteratorExit() {
        ITERATOR_UPDATER.decrementAndGet(this);
    }

    private static final AtomicIntegerFieldUpdater<HashState> ITERATOR_UPDATER = AtomicIntegerFieldUpdater.newUpdater(HashState.class, "iteratorCount");

    public interface ObjectIntObjectIntPredicate<Key1, Key2> {
        boolean test(Key1 key1, int hash1, Key2 key2, int hash2);
    }

    protected RubyHash rubyHash;
    protected int size = 0;
    protected int generation = 0; // generation count for O(1) clears
    protected int start;
    protected int end;
    protected Base[] entries;
    protected int[] hashes;
    private boolean allSymbols;
    protected ToIntFunction<Key> hash;
    protected BiPredicate<Key, Key> keyEqual;
    protected final ObjectIntObjectIntPredicate<Key, Key> exist;
}

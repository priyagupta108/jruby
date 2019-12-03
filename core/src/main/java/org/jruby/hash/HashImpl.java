/***** BEGIN LICENSE BLOCK *****
 * Version: EPL 2.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Eclipse Public
 * License Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/epl-v20.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2001 Chad Fowler <chadfowler@chadfowler.com>
 * Copyright (C) 2001 Alan Moore <alan_moore@gmx.net>
 * Copyright (C) 2001-2002 Benoit Cerrina <b.cerrina@wanadoo.fr>
 * Copyright (C) 2001-2004 Jan Arne Petersen <jpetersen@uni-bonn.de>
 * Copyright (C) 2002-2004 Anders Bengtsson <ndrsbngtssn@yahoo.se>
 * Copyright (C) 2004-2006 Thomas E Enebo <enebo@acm.org>
 * Copyright (C) 2004 Stefan Matthias Aust <sma@3plus4.de>
 * Copyright (C) 2005 Charles O Nutter <headius@headius.com>
 * Copyright (C) 2006 Ola Bini <Ola.Bini@ki.se>
 * Copyright (C) 2006 Tim Azzopardi <tim@tigerfive.com>
 * Copyright (C) 2006 Miguel Covarrubias <mlcovarrubias@gmail.com>
 * Copyright (C) 2007 MenTaLguY <mental@rydia.net>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the EPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the EPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/

package org.jruby.hash;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyObject;
import org.jruby.RubySymbol;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.Block;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;

import static org.jruby.RubyEnumerator.enumeratorizeWithSize;

/**
   The original package implemented classic bucket-based hash tables
   with entries doubly linked for an access by their insertion order.
   To decrease pointer chasing and as a consequence to improve a data
   locality the current implementation is based on storing entries in
   an array and using hash tables with open addressing.  The current
   entries are more compact in comparison with the original ones and
   this also improves the data locality.
   The hash table has two arrays called *bins* and *entries*.
     bins:
    -------
   |       |                  entries array:
   |-------|            --------------------------------
   | index |           |      | entry:  |        |      |
   |-------|           |      |         |        |      |
   | ...   |           | ...  | hash    |  ...   | ...  |
   |-------|           |      | key     |        |      |
   | empty |           |      | record  |        |      |
   |-------|            --------------------------------
   | ...   |                   ^                  ^
   |-------|                   |_ entries start   |_ entries bound
   |deleted|
    -------
   o The entry array contains table entries in the same order as they
     were inserted.
     When the first entry is deleted, a variable containing index of
     the current first entry (*entries start*) is changed.  In all
     other cases of the deletion, we just mark the entry as deleted by
     using a reserved hash value.
     Such organization of the entry storage makes operations of the
     table shift and the entries traversal very fast.
     To keep the objects small, we store keys and values in the same array
     like this:
    |---------|
    | key 1   |
    |---------|
    | value 1 |
    |---------|
    | key 2   |
    |-------  |
    | value 2 |
    |---------|
    |...      |
     ---------
     This means keys are always stored at INDEX * 2 and values are always
     stored at (INDEX * 2) + 1.
   o The bins provide access to the entries by their keys.  The
     key hash is mapped to a bin containing *index* of the
     corresponding entry in the entry array.
     The bin array size is always power of two, it makes mapping very
     fast by using the corresponding lower bits of the hash.
     Generally it is not a good idea to ignore some part of the hash.
     But alternative approach is worse.  For example, we could use a
     modulo operation for mapping and a prime number for the size of
     the bin array.  Unfortunately, the modulo operation for big
     64-bit numbers are extremely slow (it takes more than 100 cycles
     on modern Intel CPUs).
     Still other bits of the hash value are used when the mapping
     results in a collision.  In this case we use a secondary hash
     value which is a result of a function of the collision bin
     index and the original hash value.  The function choice
     guarantees that we can traverse all bins and finally find the
     corresponding bin as after several iterations the function
     becomes a full cycle linear congruential generator because it
     satisfies requirements of the Hull-Dobell theorem.
     When an entry is removed from the table besides marking the
     hash in the corresponding entry described above, we also mark
     the bin by a special value in order to find entries which had
     a collision with the removed entries.
     There are two reserved values for the bins.  One denotes an
     empty bin, another one denotes a bin for a deleted entry.
   o The length of the bin array is at least two times more than the
     entry array length.  This keeps the table load factor healthy.
     The trigger of rebuilding the table is always a case when we can
     not insert an entry anymore at the entries bound.  We could
     change the entries bound too in case of deletion but than we need
     a special code to count bins with corresponding deleted entries
     and reset the bin values when there are too many bins
     corresponding deleted entries
     Table rebuilding is done by creation of a new entry array and
     bins of an appropriate size.  We also try to reuse the arrays
     in some cases by compacting the array and removing deleted
     entries.
   o To save memory very small tables have no allocated arrays
     bins.  We use a linear search for an access by a key.
     However, we maintain an hashes array in this case for a fast skip
     when iterating over the entries array.
*/
public abstract class HashImpl extends RubyObject implements Map {
    protected volatile int iteratorCount;
    IRubyObject[] entries;
    int[] hashes;
    int[] bins;

    protected volatile HashStrategy strategy;

    long extents = 0;
    public int size = 0;

    protected IRubyObject ifNone;

    public HashImpl(Ruby runtime, RubyClass klass) {
        super(runtime, klass);
        this.ifNone = UNDEF;
        this.strategy = LINEAR;

        LINEAR.alloc(this, 0);
    }

    public HashImpl(Ruby runtime, IRubyObject defaultValue) {
        super(runtime, runtime.getHash());
        this.ifNone = defaultValue;
        this.strategy = LINEAR;

        LINEAR.alloc(this, 0);
    }

    public HashImpl(Ruby runtime, IRubyObject defaultValue, int buckets) {
        this(runtime, buckets, true);
        this.ifNone = defaultValue;
    }

    protected HashImpl(Ruby runtime, RubyClass metaClass, IRubyObject defaultValue) {
        super(runtime, metaClass);
        this.ifNone = defaultValue;
    }

    /*
     *  Constructor for internal usage (mainly for Array#|, Array#&, Array#- and Array#uniq)
     *  it doesn't initialize ifNone field
     */
    protected HashImpl(Ruby runtime, int buckets, boolean objectSpace) {
        super(runtime, runtime.getHash(), objectSpace);
        // FIXME: current hash implementation cannot deal with no buckets so we will add a single one
        //  (this constructor will go away once open addressing is added back ???)
        if (buckets <= 0) buckets = 1;
        allocFirst(buckets);
    }

    // TODO should this be deprecated ? (to be efficient, internals should deal with RubyHash directly)
    public HashImpl(Ruby runtime, Map valueMap, IRubyObject defaultValue) {
        super(runtime, runtime.getHash());
        this.ifNone = defaultValue;
        this.strategy = LINEAR;

        LINEAR.alloc(this, 0);

        for (Iterator iter = valueMap.entrySet().iterator();iter.hasNext();) {
            Entry e = (Entry)iter.next();
            internalPut((IRubyObject)e.getKey(), (IRubyObject)e.getValue());
        }
    }

    protected final void allocFirst(final int buckets) {
        if (buckets <= 0) throw new ArrayIndexOutOfBoundsException("invalid bucket size: " + buckets);

        HashStrategy strategy;

        if (buckets <= MAX_CAPACITY_FOR_TABLES_WITHOUT_BINS) {
            this.strategy = strategy = LINEAR;
        } else {
            this.strategy = strategy = ADDRESSED;
        }

        strategy.alloc(this, buckets);
    }

    static int nextPowOfTwo(final int i) {
        return Integer.MIN_VALUE >>> Integer.numberOfLeadingZeros(i - 1) << 1; // i > 1
    }

    private final void alloc() {
        generation++;
        strategy.alloc(this, 0);
    }

    /* ============================
     * Here are hash internals
     * (This could be extracted to a separate class but it's not too large though)
     * ============================
     */

    private static final int MAX_POWER2_FOR_TABLES_WITHOUT_BINS = 3;
    private static final int MAX_CAPACITY_FOR_TABLES_WITHOUT_BINS = 1 << MAX_POWER2_FOR_TABLES_WITHOUT_BINS;
    static final int MRI_INITIAL_CAPACITY = 8;
    private static final int NUMBER_OF_ENTRIES = 2;

    private int generation = 0; // generation count for O(1) clears

    private static final int HASH_SIGN_BIT_MASK = ~(1 << 31);

    private final synchronized void resize(final int newCapacity) {
        strategy.resize(this, newCapacity);
    }

    static int START(long startEnd) {
        return (int) (startEnd >>> 32);
    }

    static int END(long startEnd) {
        return (int) startEnd;
    }

    protected final int hashValue(final IRubyObject key) {
        final int h = isComparedByIdentity() ? System.identityHashCode(key) : key.hashCode();
        return h & HASH_SIGN_BIT_MASK;
    }

    void checkResize() {
        if (getLength() == getEnd()) {
            resize(entries.length << 2);
            return;
        }
    }

    protected final void checkIterating() {
        if (iteratorCount > 0) {
            throw metaClass.getClassRuntime().newRuntimeError("can't add a new key into hash during iteration");
        }
    }

    static final HashStrategy LINEAR = new LinearHashStrategy();
    static final HashStrategy ADDRESSED = new AddressedHashStrategy();

    protected void clearAll() {
        if (size > 0) {
            alloc();
            extents = size = 0;
        }
    }

    protected boolean compactEntries(ThreadContext context) {
        boolean changed = false;

        IRubyObject value, key;

        long extents = this.extents;
        int start = START(extents);
        int end = END(extents);
        IRubyObject[] entries = this.entries;

        for (int i = start; i < end; i++) {
            value = entryValue(entries, i);
            if (value == context.nil) {
                key = entryKey(entries, i);
                internalDelete(key);
                changed = true;
            }
        }
        return changed;
    }

    protected IRubyObject anyPattern(ThreadContext context, IRubyObject pattern) {
        iteratorEntry();
        try {
            long extents = this.extents;
            int start = START(extents);
            int end = END(extents);
            IRubyObject[] entries = this.entries;

            for (int i = start; i < end; i++) {
                IRubyObject key = entryKey(entries, i);
                IRubyObject value = entryValue(entries, i);

                if (key == null || value == null) continue;

                IRubyObject newAssoc = RubyArray.newArray(context.runtime, key, value);
                if (pattern.callMethod(context, "===", newAssoc).isTrue())
                    return context.tru;
            }
            return context.fals;
        } finally {
            iteratorExit();
        }
    }

    protected IRubyObject anyIterator(ThreadContext context, Block block) {
        iteratorEntry();
        try {
            long extents = this.extents;
            int start = START(extents);
            int end = END(extents);
            IRubyObject[] entries = this.entries;

            for (int i = start; i < end; i++) {
                IRubyObject key = entryKey(entries, i);
                IRubyObject value = entryValue(entries, i);

                if (key == null || value == null) continue;

                IRubyObject newAssoc = RubyArray.newArray(context.runtime, key, value);
                if (block.yield(context, newAssoc).isTrue()) return context.tru;
            }
            return context.fals;
        } finally {
            iteratorExit();
        }
    }

    protected IRubyObject anyIteratorFast(ThreadContext context, Block block) {
        iteratorEntry();
        try {
            long extents = this.extents;
            int start = START(extents);
            int end = END(extents);
            IRubyObject[] entries = this.entries;

            for (int i = start; i < end; i++) {
                IRubyObject key = entryKey(entries, i);
                IRubyObject value = entryValue(entries, i);

                if (key == null || value == null) continue;

                if (block.yieldArray(context, context.runtime.newArray(key, value), null).isTrue()) return context.tru;
            }
            return context.fals;
        } finally {
            iteratorExit();
        }
    }

    public IRubyObject internalPut(final IRubyObject key, final IRubyObject value) {
      checkResize();
      final int hash = hashValue(key);

      return strategy.put(this, key, hash, value);
    }

    public final boolean internalPutIfNoKey(final IRubyObject key, final IRubyObject value) {
        if (internalGetEntry(key) == RubyHash.NO_ENTRY) {
            internalPut(key, value);
            return true;
        }
        return false;
    }

    @Deprecated // no longer used
    protected final IRubyObject internalJavaPut(final IRubyObject key, final IRubyObject value) {
        return internalPut(key, value);
    }

    private final int getLength() {
        return entries.length / NUMBER_OF_ENTRIES;
    }

    private final boolean shouldSearchLinear() {
        return getLength() <= MAX_CAPACITY_FOR_TABLES_WITHOUT_BINS;
    }

    int getEnd() {
        return END(extents);
    }

    void setEnd(int newEnd) {
        extents = (extents & 0xFFFFFFFF00000000L) | newEnd;
    }

    private int getStart() {
        return START(extents);
    }

    private void setStart(int newStart) {
        extents = (extents & 0xFFFFFFFFL) | (((long) newStart) << 32);
    }

    static IRubyObject entryKey(IRubyObject[] entries, int index) {
        return entries[index * NUMBER_OF_ENTRIES];
    }

    static IRubyObject entryValue(IRubyObject[] entries, int index) {
        return entries[index * NUMBER_OF_ENTRIES + 1];
    }

    static IRubyObject entryValue(IRubyObject[] entries, int index, IRubyObject value) {
        return entries[index * NUMBER_OF_ENTRIES + 1] = value;
    }

    static void set(IRubyObject[] entries, int index, IRubyObject key, IRubyObject value) {
        entries[index * NUMBER_OF_ENTRIES] = key;
        entries[index * NUMBER_OF_ENTRIES + 1] = value;
    }

    static void unset(IRubyObject[] entries, int index) {
        set(entries, index, null, null);
    }

    protected IRubyObject internalGet(IRubyObject key) { // specialized for value
        if (isEmpty()) return null;
        final int hash = hashValue(key);

        return strategy.get(this, key, hash);
    }

    static boolean internalKeyExist(IRubyObject key, int hash, IRubyObject otherKey, int otherHash, boolean identity) {
        return (hash == otherHash && (key == otherKey || (!identity && key.eql(otherKey))));
    }

    // delete implementation

    protected IRubyObject internalDelete(final IRubyObject key) {
        if (isEmpty()) return null;
        return internalDelete(hashValue(key), MATCH_KEY, key, null);
    }

    protected IRubyObject internalDeleteEntry(final IRubyObject key, final IRubyObject value) {
        // n.b. we need to recompute the hash in case the key object was modified
        return internalDelete(hashValue(key), MATCH_ENTRY, key, value);
    }

    void updateStartAndEndPointer() {
        if (isEmpty()) {
            extents = 0;
        } else {
            IRubyObject[] entries = this.entries;
            long extents = this.extents;
            int start = START(extents);
            int end = END(extents);

            while (entryKey(entries, start) == null) {
                start++;
            }

            while((end - 1) > 0 && entryKey(entries, end - 1) == null) {
                end--;
            }

            setExtents(start, end);
        }
    }

    void setExtents(int start, int end) {
        extents = (((long) start) << 32) | end;
    }

    private int lastElementsIndex() {
        return getEnd() - 1;
    }

    private final IRubyObject internalDelete(final int hash, final EntryMatchType matchType, final IRubyObject key, final IRubyObject value) {
        if (isEmpty()) return null;

        return strategy.delete(this, matchType, key, hash, value);
    }

    public static abstract class EntryMatchType {
        public abstract boolean matches(final IRubyObject key, final IRubyObject value, final IRubyObject otherKey, final IRubyObject otherValue);
    }

    private static final EntryMatchType MATCH_KEY = new EntryMatchType() {
        @Override
        public boolean matches(final IRubyObject key, final IRubyObject value, final IRubyObject otherKey, final IRubyObject otherValue) {
            return key == otherKey || key.eql(otherKey);
        }
    };

    private static final EntryMatchType MATCH_ENTRY = new EntryMatchType() {
        @Override
        public boolean matches(final IRubyObject key, final IRubyObject value, final IRubyObject otherKey, final IRubyObject otherValue) {
            return (key == otherKey || key.eql(otherKey)) &&
                (value == otherValue || value.equals(otherValue));
        }
    };

    final IRubyObject[] internalCopyTable() {
        IRubyObject[] entries = this.entries;
        IRubyObject[] newTable = new RubyObject[entries.length];
        System.arraycopy(entries, 0, newTable, 0, entries.length);
        return newTable;
    }

    final int[] internalCopyHashes() {
        int[] hashes = this.hashes;
        int[] newHashes = new int[hashes.length];
        System.arraycopy(hashes, 0, newHashes, 0, hashes.length);
        return newHashes;
    }

    protected <T> void visitLimited(ThreadContext context, RubyHash.VisitorWithState visitor, long size, T state) {
        int startGeneration = generation;
        long count = size;
        int index = 0;

        long extents = this.extents;
        int start = START(extents);
        int end = END(extents);
        IRubyObject[] entries = this.entries;

        for (int i = start; i < end && count != 0; i++) {
            if (startGeneration != generation) {
                startGeneration = generation;
                i = start;
            }

            IRubyObject key = entryKey(entries, i);
            IRubyObject value = entryValue(entries, i);

            if(key == null || value == null) continue;

            visitor.visit(context, (RubyHash) this, key, value, index++, state);
            count--;
        }

        // it does not handle all concurrent modification cases,
        // but at least provides correct marshal as we have exactly size entries visited (count == 0)
        // or if count < 0 - skipped concurrent modification checks
        if (count > 0) throw concurrentModification();
    }

    protected RubyHash.RubyHashEntry internalGetEntry(IRubyObject key) {
        IRubyObject value = internalGet(key);
        return value == null ? RubyHash.NO_ENTRY : new RubyHash.RubyHashEntry(key, value, (RubyHash) this);
    }

    public <T> boolean allSymbols() {
        int startGeneration = generation;

        long extents = this.extents;
        int start = START(extents);
        int end = END(extents);
        IRubyObject[] entries = this.entries;

        for (int i = start; i < end; i++) {
            int currentGeneration = generation;
            if (startGeneration != currentGeneration) {
                startGeneration = currentGeneration;
                i = start;
            }

            IRubyObject key = entryKey(entries, i);
            if (key != null && !(key instanceof RubySymbol)) return false;
        }
        return true;
    }

    private static final AtomicIntegerFieldUpdater<HashImpl> ITERATOR_UPDATER;
    static {
        AtomicIntegerFieldUpdater<HashImpl> iterUp = null;
        try {
            iterUp = AtomicIntegerFieldUpdater.newUpdater(HashImpl.class, "iteratorCount");
        } catch (Exception e) {
            // ignore, leave null
        }
        ITERATOR_UPDATER = iterUp;
    }

    protected void iteratorEntry() {
        if (ITERATOR_UPDATER == null) {
            iteratorEntrySync();
            return;
        }
        ITERATOR_UPDATER.incrementAndGet(this);
    }

    protected void iteratorExit() {
        if (ITERATOR_UPDATER == null) {
            iteratorExitSync();
            return;
        }
        ITERATOR_UPDATER.decrementAndGet(this);
    }

    private synchronized void iteratorEntrySync() {
        ++iteratorCount;
    }

    private synchronized void iteratorExitSync() {
        --iteratorCount;
    }

    public IRubyObject shift(ThreadContext context) {
        long extents = this.extents;
        int start = START(extents);
        int end = END(extents);

        IRubyObject[] entries = this.entries;
        IRubyObject key = entryKey(entries, start);
        IRubyObject value = entryValue(entries, start);

        if (getLength() == end || key != entryKey(entries, end)) {
            RubyArray result = RubyArray.newArray(context.runtime, key, value);
            internalDeleteEntry(key, value);
            return result;
        }

        // no entry
        return null;
    }

    protected static abstract class EntryView {
        public abstract Object convertEntry(Ruby runtime, RubyHash hash, IRubyObject key, IRubyObject value);
        public abstract boolean contains(RubyHash hash, Object o);
        public abstract boolean remove(RubyHash hash, Object o);
    }

    protected class BaseIterator implements Iterator {
        final private RubyHash.EntryView view;
        private IRubyObject key, value;
        private boolean peeking, hasNext;
        private int startGeneration, index, end;

        public BaseIterator(RubyHash.EntryView view) {
            this.view = view;
            this.startGeneration = HashImpl.this.generation;
            long extents = HashImpl.this.extents;
            int start = START(extents);
            int end = END(extents);
            this.index = start;
            this.end = end;
            this.hasNext = HashImpl.this.size > 0;
        }

        private void advance(boolean consume) {
            if (!peeking) {
                do {
                    IRubyObject[] entries = HashImpl.this.entries;
                    if (startGeneration != HashImpl.this.generation) {
                        startGeneration = HashImpl.this.generation;
                        index = getStart();
                        key = entryKey(entries, index);
                        value = entryValue(entries, index);
                        index++;
                        hasNext = HashImpl.this.size > 0;
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
            return view.convertEntry(getRuntime(), (RubyHash) HashImpl.this, key, value);
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
            internalDeleteEntry(key, value);
        }
    }

    protected abstract boolean isComparedByIdentity();
    protected abstract RaiseException concurrentModification();
}

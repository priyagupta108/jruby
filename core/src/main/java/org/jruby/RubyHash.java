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

package org.jruby;

import org.jcodings.specific.USASCIIEncoding;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.common.IRubyWarnings.ID;
import org.jruby.exceptions.RaiseException;
import org.jruby.hash.HashImpl;
import org.jruby.javasupport.JavaUtil;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.CallBlock19;
import org.jruby.runtime.ClassIndex;
import org.jruby.runtime.Helpers;
import org.jruby.runtime.JavaSites.HashSites;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.Signature;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.marshal.MarshalStream;
import org.jruby.runtime.marshal.UnmarshalStream;
import org.jruby.util.ByteList;
import org.jruby.util.RecursiveComparator;
import org.jruby.util.TypeConverter;

import java.io.IOException;
import java.util.AbstractCollection;
import java.util.AbstractSet;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import static org.jruby.RubyEnumerator.enumeratorizeWithSize;
import static org.jruby.runtime.Visibility.PRIVATE;
import static org.jruby.RubyEnumerator.SizeFn;

/** Implementation of the Hash class.
 *
 *  Concurrency: no synchronization is required among readers, but
 *  all users must synchronize externally with writers.
 *
 */
@JRubyClass(name = "Hash", include="Enumerable")
public class RubyHash extends HashImpl {
    public static final int DEFAULT_INSPECT_STR_SIZE = 20;

    public static final int COMPARE_BY_IDENTITY_F = ObjectFlags.COMPARE_BY_IDENTITY_F;

    public static RubyClass createHashClass(Ruby runtime) {
        RubyClass hashc = runtime.defineClass("Hash", runtime.getObject(), HASH_ALLOCATOR);
        runtime.setHash(hashc);

        hashc.setClassIndex(ClassIndex.HASH);
        hashc.setReifiedClass(RubyHash.class);

        hashc.kindOf = new RubyModule.JavaClassKindOf(RubyHash.class);

        hashc.includeModule(runtime.getEnumerable());

        hashc.defineAnnotatedMethods(RubyHash.class);

        return hashc;
    }

    private final static ObjectAllocator HASH_ALLOCATOR = new ObjectAllocator() {
        @Override
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new RubyHash(runtime, klass);
        }
    };

    @Override
    public ClassIndex getNativeClassIndex() {
        return ClassIndex.HASH;
    }

    /** rb_hash_s_create
     *
     */
    @JRubyMethod(name = "[]", rest = true, meta = true)
    public static IRubyObject create(ThreadContext context, IRubyObject recv, IRubyObject[] args, Block block) {
        final Ruby runtime = context.runtime;

        if (args.length == 1) {
            IRubyObject tmp = TypeConverter.convertToTypeWithCheck(args[0], runtime.getHash(), "to_hash");

            if (!tmp.isNil()) {
                return new RubyHash(runtime, (RubyClass) recv, tmp);
            }

            final IRubyObject nil = context.nil;
            tmp = TypeConverter.convertToTypeWithCheck(args[0], runtime.getArray(), "to_ary");
            if (tmp != nil) {
                RubyHash hash = (RubyHash) ((RubyClass) recv).allocate();
                RubyArray arr = (RubyArray) tmp;
                for (int i = 0, j = arr.getLength(); i<j; i++) {
                    IRubyObject e = arr.entry(i);
                    IRubyObject v = TypeConverter.convertToTypeWithCheck(e, runtime.getArray(), "to_ary");
                    IRubyObject key;
                    IRubyObject val = nil;
                    if (v == nil) {
                        runtime.getWarnings().warn("wrong element type " + e.getMetaClass() + " at " + i + " (expected array)");
                        runtime.getWarnings().warn("ignoring wrong elements is deprecated, remove them explicitly");
                        runtime.getWarnings().warn("this causes ArgumentError in the next release");
                        continue;
                    }
                    switch (((RubyArray) v).getLength()) {
                    default:
                        throw runtime.newArgumentError("invalid number of elements (" + ((RubyArray) v).getLength() + " for 1..2)");
                    case 2:
                        val = ((RubyArray) v).entry(1);
                    case 1:
                        key = ((RubyArray) v).entry(0);
                        hash.fastASetCheckString(runtime, key, val);
                    }
                }
                return hash;
            }
        }

        if ((args.length & 1) != 0) {
            throw runtime.newArgumentError("odd number of arguments for Hash");
        }

        RubyHash hash = (RubyHash) ((RubyClass) recv).allocate();
        for (int i=0; i < args.length; i+=2) hash.fastASetCheckString(runtime, args[i], args[i+1]);

        return hash;
    }

    @JRubyMethod(name = "try_convert", meta = true)
    public static IRubyObject try_convert(ThreadContext context, IRubyObject recv, IRubyObject args) {
        return TypeConverter.convertToTypeWithCheck(args, context.runtime.getHash(), "to_hash");
    }

    /** rb_hash_new
     *
     */
    public static final RubyHash newHash(Ruby runtime) {
        return new RubyHash(runtime);
    }

    /** rb_hash_new
     *
     */
    public static RubyHash newKwargs(Ruby runtime, String key, IRubyObject value) {
        RubyHash kwargs = new RubyHash(runtime);
        kwargs.fastASet(runtime.newSymbol(key), value);
        return kwargs;
    }

    /** rb_hash_new
     *
     */
    public static final RubyHash newHash(Ruby runtime, Map valueMap, IRubyObject defaultValue) {
        assert defaultValue != null;

        return new RubyHash(runtime, valueMap, defaultValue);
    }

    private static final int PROCDEFAULT_HASH_F = ObjectFlags.PROCDEFAULT_HASH_F;

    public RubyHash(Ruby runtime, RubyClass klass) {
        super(runtime, klass);
    }

    public RubyHash(Ruby runtime, int buckets) {
        this(runtime, UNDEF, buckets);
    }

    public RubyHash(Ruby runtime) {
        this(runtime, UNDEF);
    }

    public RubyHash(Ruby runtime, IRubyObject defaultValue) {
        super(runtime, defaultValue);
    }

    public RubyHash(Ruby runtime, IRubyObject defaultValue, int buckets) {
        super(runtime, defaultValue, buckets);
    }

    protected RubyHash(Ruby runtime, RubyClass metaClass, IRubyObject defaultValue) {
        super(runtime, metaClass, defaultValue);
    }

    /*
     *  Constructor for internal usage (mainly for Array#|, Array#&, Array#- and Array#uniq)
     *  it doesn't initialize ifNone field
     */
    RubyHash(Ruby runtime, int buckets, boolean objectSpace) {
        super(runtime, buckets, objectSpace);
    }

    // TODO should this be deprecated ? (to be efficient, internals should deal with RubyHash directly)
    public RubyHash(Ruby runtime, Map valueMap, IRubyObject defaultValue) {
        super(runtime, valueMap, defaultValue);
    }

    public static final RubyHashEntry NO_ENTRY = new RubyHashEntry();

    public static final class RubyHashEntry implements Map.Entry {
        final IRubyObject key;
        IRubyObject value;
        private RubyHash hash;

        RubyHashEntry() {
            key = NEVER;
        }

        public RubyHashEntry(IRubyObject k, IRubyObject v, RubyHash h) {
            key = k; value = v; hash = h;
        }

        public RubyHashEntry(IRubyObject k, IRubyObject v) {
            key = k; value = v;
        }

        @Override
        public Object getKey() {
            return key;
        }
        public Object getJavaifiedKey(){
            return key.toJava(Object.class);
        }

        @Override
        public Object getValue() {
            return value;
        }
        public Object getJavaifiedValue() {
            return value.toJava(Object.class);
        }

        @Override
        public Object setValue(Object value) {
            IRubyObject oldValue = this.value;
            if (value instanceof IRubyObject) {
                IRubyObject rubyValue = (IRubyObject)value;
                this.value = rubyValue;
                this.hash.internalPut(key, rubyValue);
            } else {
                throw new UnsupportedOperationException("directEntrySet() doesn't support setValue for non IRubyObject instance entries, convert them manually or use entrySet() instead");
            }
            return oldValue;
        }

        @Override
        public boolean equals(Object other){
            if(!(other instanceof RubyHashEntry)) return false;
            RubyHashEntry otherEntry = (RubyHashEntry)other;

            return (key == otherEntry.key || key.eql(otherEntry.key)) &&
                    (value == otherEntry.value || value.equals(otherEntry.value));
        }

        @Override
        public int hashCode(){
            return key.hashCode() ^ value.hashCode();
        }
    }

    final RubyHashEntry getEntry(IRubyObject key) {
        return internalGetEntry(key);
    }

    public static abstract class VisitorWithState<T> {
        public abstract void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, T state);
    }

    public static abstract class Visitor extends VisitorWithState {
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, Object state) {
            visit(key, value);
        }
        public abstract void visit(IRubyObject key, IRubyObject value);
    }

    public <T> void visitAll(ThreadContext context, VisitorWithState visitor, T state) {
        // use -1 to disable concurrency checks
        visitLimited(context, visitor, -1, state);
    }

    public <T> boolean allSymbols() {
        return super.allSymbols();
    }

    /* ============================
     * End of hash internals
     * ============================
     */

    /*  ================
     *  Instance Methods
     *  ================
     */

    /** rb_hash_initialize
     *
     */
    @JRubyMethod(optional = 1, visibility = PRIVATE)
    public IRubyObject initialize(IRubyObject[] args, final Block block) {
        modify();

        if (block.isGiven()) {
            if (args.length > 0) throw metaClass.runtime.newArgumentError("wrong number of arguments");
            ifNone = metaClass.runtime.newProc(Block.Type.PROC, block);
            flags |= PROCDEFAULT_HASH_F;
        } else {
            Arity.checkArgumentCount(metaClass.runtime, args, 0, 1);
            if (args.length == 1) ifNone = args[0];
            if (args.length == 0) ifNone = UNDEF;
        }
        return this;
    }

    @JRubyMethod(name = "default")
    public IRubyObject default_value_get(ThreadContext context) {
        if ((flags & PROCDEFAULT_HASH_F) != 0) {
            return context.nil;
        }
        return ifNone == UNDEF ? context.nil : ifNone;
    }

    @JRubyMethod(name = "default")
    public IRubyObject default_value_get(ThreadContext context, IRubyObject arg) {
        if ((flags & PROCDEFAULT_HASH_F) != 0) {
            return sites(context).call.call(context, ifNone, ifNone, this, arg);
        }
        return ifNone == UNDEF ? context.nil : ifNone;
    }

    /** rb_hash_set_default
     *
     */
    @JRubyMethod(name = "default=", required = 1)
    public IRubyObject default_value_set(ThreadContext context, final IRubyObject defaultValue) {
        modify();

        ifNone = defaultValue;
        flags &= ~PROCDEFAULT_HASH_F;

        return ifNone;
    }

    /** rb_hash_default_proc
     *
     */
    @JRubyMethod
    public IRubyObject default_proc(ThreadContext context) {
        return (flags & PROCDEFAULT_HASH_F) != 0 ? ifNone : context.nil;
    }

    /** default_proc_arity_check
     *
     */
    private void checkDefaultProcArity(IRubyObject proc) {
        int n = ((RubyProc)proc).getBlock().getSignature().arityValue();

        if(((RubyProc)proc).getBlock().type == Block.Type.LAMBDA && n != 2 && (n >= 0 || n < -3)) {
            if(n < 0) n = -n-1;
            throw getRuntime().newTypeError("default_proc takes two arguments (2 for " + n + ")");
        }
    }

    /** rb_hash_set_default_proc
     *
     */
    @JRubyMethod(name = "default_proc=")
    public IRubyObject set_default_proc(ThreadContext context, IRubyObject proc) {
        modify();

        if (proc.isNil()) {
            ifNone = proc;
            flags &= ~PROCDEFAULT_HASH_F;
            return proc;
        }

        Ruby runtime = context.runtime;

        IRubyObject b = TypeConverter.convertToType(proc, runtime.getProc(), "to_proc");
        if (b.isNil() || !(b instanceof RubyProc)) {
            throw runtime.newTypeError("wrong default_proc type " + proc.getMetaClass() + " (expected Proc)");
        }
        proc = b;
        checkDefaultProcArity(proc);
        ifNone = proc;
        flags |= PROCDEFAULT_HASH_F;
        return proc;
    }

    /** rb_hash_modify
     *
     */
    public void modify() {
    	testFrozen("Hash");
    }

    /** inspect_hash
     *
     */
    private IRubyObject inspectHash(final ThreadContext context) {
        final RubyString str = RubyString.newStringLight(context.runtime, DEFAULT_INSPECT_STR_SIZE, USASCIIEncoding.INSTANCE);

        str.infectBy(this);

        str.cat((byte)'{');

        visitAll(context, InspectVisitor, str);
        str.cat((byte)'}');
        return str;
    }

    private static final VisitorWithState<RubyString> InspectVisitor = new VisitorWithState<RubyString>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, RubyString str) {
            RubyString keyStr = inspect(context, key);
            RubyString valStr = inspect(context, value);

            final ByteList bytes = str.getByteList();
            bytes.ensure(2 + keyStr.size() + 2 + valStr.size());

            if (index > 0) bytes.append((byte) ',').append((byte) ' ');

            str.cat19(keyStr);
            bytes.append((byte) '=').append((byte) '>');
            str.cat19(valStr);
        }
    };

    @Override
    public IRubyObject inspect() {
        return inspect(metaClass.runtime.getCurrentContext());
    }

    /** rb_hash_inspect
     *
     */
    @JRubyMethod(name = "inspect")
    public IRubyObject inspect(ThreadContext context) {
        if (isEmpty()) return RubyString.newUSASCIIString(context.runtime, "{}");
        if (context.runtime.isInspecting(this)) return RubyString.newUSASCIIString(context.runtime, "{...}");

        try {
            context.runtime.registerInspecting(this);
            return inspectHash(context);
        } finally {
            context.runtime.unregisterInspecting(this);
        }
    }

    @Deprecated
    public IRubyObject inspect19(ThreadContext context) {
        return inspect(context);
    }

    /** rb_hash_size
     *
     */
    @JRubyMethod(name = {"size", "length"})
    public RubyFixnum rb_size(ThreadContext context) {
        return context.runtime.newFixnum(size);
    }

    private SizeFn enumSizeFn() {
        return (context, args) -> this.rb_size(context);
    }

    /** rb_hash_empty_p
     *
     */
    @JRubyMethod(name = "empty?")
    public RubyBoolean empty_p(ThreadContext context) {
        return size == 0 ? context.tru : context.fals;
    }

    /** rb_hash_to_a
     *
     */
    @JRubyMethod(name = "to_a")
    @Override
    public RubyArray to_a(ThreadContext context) {
        final Ruby runtime = context.runtime;
        try {
            final RubyArray result = RubyArray.newBlankArrayInternal(runtime, size);

            visitAll(context, RubyHash.StoreKeyValueVisitor, result);

            result.setTaint(isTaint());
            return result;
        } catch (NegativeArraySizeException nase) {
            throw concurrentModification();
        }
    }

    private static final VisitorWithState<RubyArray> StoreKeyValueVisitor = new VisitorWithState<RubyArray>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, RubyArray result) {
            result.storeInternal(index, RubyArray.newArray(context.runtime, key, value));
        }
    };

    /** rb_hash_to_s & to_s_hash
     *
     */
    @JRubyMethod(name = "to_s")
    public IRubyObject to_s(ThreadContext context) {
        return inspect(context);
    }

    public final IRubyObject to_s19(ThreadContext context) {
        return to_s(context);
    }

    /** rb_hash_rehash
     *
     */
    @JRubyMethod(name = "rehash")
    public RubyHash rehash(ThreadContext context) {
        if (iteratorCount > 0) {
            throw context.runtime.newRuntimeError("rehash during iteration");
        }

        modify();

        strategy.rehash(this);

        return this;
    }

    /** rb_hash_to_hash
     *
     */
    @JRubyMethod(name = "to_hash")
    public RubyHash to_hash(ThreadContext context) {
        return this;
    }

    @JRubyMethod
    public RubyHash to_h(ThreadContext context) {
        final Ruby runtime = context.runtime;
        return getType() == runtime.getHash() ? this : newHash(runtime).replace(context, this);
    }

    @Override
    public RubyHash convertToHash() {
        return this;
    }

    public final void fastASet(IRubyObject key, IRubyObject value) {
        internalPut(key, value);
    }

    public final void fastASetCheckString(Ruby runtime, IRubyObject key, IRubyObject value) {
      if (key instanceof RubyString && !isComparedByIdentity()) {
          op_asetForString(runtime, (RubyString) key, value);
      } else {
          internalPut(key, value);
      }
    }

    public final void fastASet(Ruby runtime, IRubyObject key, IRubyObject value, boolean prepareString) {
        if (prepareString) {
            fastASetCheckString(runtime, key, value);
        } else {
            fastASet(key, value);
        }
    }

    /** rb_hash_aset
     *
     */
    @JRubyMethod(name = {"[]=", "store"})
    public IRubyObject op_aset(ThreadContext context, IRubyObject key, IRubyObject value) {
        modify();

        fastASetCheckString(context.runtime, key, value);
        return value;
    }

    protected void op_asetForString(Ruby runtime, RubyString key, IRubyObject value) {
        final int hash = hashValue(key);

        strategy.putString(this, key, hash, value);
    }

    // returns null when not found to avoid unnecessary getRuntime().getNil() call
    public final IRubyObject fastARef(IRubyObject key) {
        return internalGet(key);
    }

    public RubyBoolean compare(final ThreadContext context, VisitorWithState<RubyHash> visitor, IRubyObject other) {

        Ruby runtime = context.runtime;

        if (!(other instanceof RubyHash)) {
            if (!sites(context).respond_to_to_hash.respondsTo(context, other, other)) {
                return runtime.getFalse();
            }
            return Helpers.rbEqual(context, other, this);
        }

        final RubyHash otherHash = (RubyHash) other;

        if (this.size != otherHash.size) {
            return runtime.getFalse();
        }

        try {
            visitAll(context, visitor, otherHash);
        } catch (Mismatch e) {
            return runtime.getFalse();
        }

        return runtime.getTrue();
    }

    private static final VisitorWithState<RubyHash> FindMismatchUsingEqualVisitor = new VisitorWithState<RubyHash>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, RubyHash otherHash) {
            IRubyObject value2 = otherHash.fastARef(key);

            if (value2 == null) {
                // other hash does not contain key
                throw MISMATCH;
            }

            if (!Helpers.rbEqual(context, value, value2).isTrue()) {
                throw MISMATCH;
            }
        }
    };

    private static final VisitorWithState<RubyHash> FindMismatchUsingEqlVisitor = new VisitorWithState<RubyHash>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, RubyHash otherHash) {
            IRubyObject value2 = otherHash.fastARef(key);

            if (value2 == null) {
                // other hash does not contain key
                throw MISMATCH;
            }

            if (!Helpers.rbEql(context, value, value2).isTrue()) {
                throw MISMATCH;
            }
        }
    };

    /** rb_hash_equal
     *
     */
    @Override
    @JRubyMethod(name = "==")
    public IRubyObject op_equal(final ThreadContext context, IRubyObject other) {
        return RecursiveComparator.compare(context, FindMismatchUsingEqualVisitor, this, other);
    }

    /** rb_hash_eql
     *
     */
    @JRubyMethod(name = "eql?")
    public IRubyObject op_eql(final ThreadContext context, IRubyObject other) {
        return RecursiveComparator.compare(context, FindMismatchUsingEqlVisitor, this, other);
    }

    @Deprecated
    public IRubyObject op_eql19(final ThreadContext context, IRubyObject other) {
        return op_eql(context, other);
    }

    /** rb_hash_aref
     *
     */
    @JRubyMethod(name = "[]", required = 1)
    public IRubyObject op_aref(ThreadContext context, IRubyObject key) {
        IRubyObject value;
        return ((value = internalGet(key)) == null) ? sites(context).default_.call(context, this, this, key) : value;
    }

    /** hash_le_i
     *
     */
    private boolean hash_le(RubyHash other) {
        return other.directEntrySet().containsAll(directEntrySet());
    }

    @JRubyMethod(name = "<", required = 1)
    public IRubyObject op_lt(ThreadContext context, IRubyObject other) {
        final RubyHash otherHash = ((RubyBasicObject) other).convertToHash();
        if (size() >= otherHash.size()) return context.fals;

        return RubyBoolean.newBoolean(context.runtime, hash_le(otherHash));
    }

    @JRubyMethod(name = "<=", required = 1)
    public IRubyObject op_le(ThreadContext context, IRubyObject other) {
        final RubyHash otherHash = other.convertToHash();
        if (size() > otherHash.size()) return context.fals;

        return RubyBoolean.newBoolean(context.runtime, hash_le(otherHash));
    }

    @JRubyMethod(name = ">", required = 1)
    public IRubyObject op_gt(ThreadContext context, IRubyObject other) {
        final RubyHash otherHash = other.convertToHash();
        return otherHash.op_lt(context, this);
    }

    @JRubyMethod(name = ">=", required = 1)
    public IRubyObject op_ge(ThreadContext context, IRubyObject other) {
        final RubyHash otherHash = other.convertToHash();
        return otherHash.op_le(context, this);
    }

    /** rb_hash_hash
     *
     */
    @Override
    public RubyFixnum hash() {
        return hash(metaClass.runtime.getCurrentContext());
    }

    @JRubyMethod(name = "hash")
    public RubyFixnum hash(ThreadContext context) {
        final int size = size();
        long[] hval = { Helpers.hashStart(context.runtime, size) };
        if (size > 0) {
            iteratorVisitAll(context, CalculateHashVisitor, hval);
        }
        return context.runtime.newFixnum(hval[0]);
    }

    private static final VisitorWithState<long[]> CalculateHashVisitor = new VisitorWithState<long[]>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, long[] hval) {
            hval[0] += Helpers.safeHash(context, key).value ^ Helpers.safeHash(context, value).value;
        }
    };

    @Deprecated
    public final RubyFixnum hash19() {
        return hash(getRuntime().getCurrentContext());
    }

    /** rb_hash_fetch
     *
     */
    public IRubyObject fetch(ThreadContext context, IRubyObject[] args, Block block) {
        Arity.checkArgumentCount(context.runtime, args.length, 1, 2);

        switch(args.length) {
            case 1: return fetch(context, args[0], block);
            case 2: return fetch(context, args[0], args[1], block);
        }

        return null;
    }

    @JRubyMethod
    public IRubyObject fetch(ThreadContext context, IRubyObject key, Block block) {
        Ruby runtime = context.runtime;

        IRubyObject value = internalGet(key);

        if (value == null) {
            if (block.isGiven()) return block.yield(context, key);

            throw runtime.newKeyError("key not found: " + key.inspect(), this, key);
        }

        return value;
    }

    @JRubyMethod
    public IRubyObject fetch(ThreadContext context, IRubyObject key, IRubyObject _default, Block block) {
        Ruby runtime = context.runtime;
        boolean blockGiven = block.isGiven();

        if (blockGiven) {
            runtime.getWarnings().warn(ID.BLOCK_BEATS_DEFAULT_VALUE, "block supersedes default value argument");
        }

        IRubyObject value = internalGet(key);

        if (value == null) {
            if (blockGiven) return block.yield(context, key);

            return _default;
        }

        return value;
    }

    /** rb_hash_has_key
     *
     */
    @JRubyMethod(name = {"has_key?", "key?", "include?", "member?"}, required = 1)
    public RubyBoolean has_key_p(ThreadContext context, IRubyObject key) {
        Ruby runtime = context.runtime;
        IRubyObject result = internalGet(key);
        return result == null ? runtime.getFalse() : runtime.getTrue();
    }

    public RubyBoolean has_key_p(IRubyObject key) {
        IRubyObject result = internalGet(key);
        return result == null ? metaClass.runtime.getFalse() : metaClass.runtime.getTrue();
    }

    private static class Found extends RuntimeException {
        @Override
        public Throwable fillInStackTrace() {
            return null;
        }
    }

    private static final Found FOUND = new Found();

    private static class FoundKey extends Found {
        public final IRubyObject key;
        FoundKey(IRubyObject key) {
            super();
            this.key = key;
        }
    }

    private static class FoundPair extends FoundKey {
        public final IRubyObject value;
        FoundPair(IRubyObject key, IRubyObject value) {
            super(key);
            this.value = value;
        }
    }

    private boolean hasValue(ThreadContext context, IRubyObject expected) {
        try {
            visitAll(context, FoundIfEqualVisitor, expected);
            return false;
        } catch (Found found) {
            return true;
        }
    }

    private static final VisitorWithState<IRubyObject> FoundIfEqualVisitor = new VisitorWithState<IRubyObject>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, IRubyObject expected) {
            if (equalInternal(context, value, expected)) {
                throw FOUND;
            }
        }
    };

    /** rb_hash_has_value
     *
     */
    @JRubyMethod(name = {"has_value?", "value?"}, required = 1)
    public RubyBoolean has_value_p(ThreadContext context, IRubyObject expected) {
        return context.runtime.newBoolean(hasValue(context, expected));
    }

    private <T> void iteratorVisitAll(ThreadContext context, VisitorWithState<T> visitor, T state) {
        try {
            iteratorEntry();
            visitAll(context, visitor, state);
        } finally {
            iteratorExit();
        }
    }

    /** rb_hash_each
     *
     */
    public RubyHash eachCommon(final ThreadContext context, final Block block) {
        iteratorVisitAll(context, YieldArrayVisitor, block);

        return this;
    }

    private static final VisitorWithState<Block> YieldArrayVisitor = new VisitorWithState<Block>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, Block block) {
            block.yieldArray(context, context.runtime.newArray(key, value), null);
        }
    };

    @JRubyMethod(name = {"each", "each_pair"})
    public IRubyObject each(final ThreadContext context, final Block block) {
        return block.isGiven() ? each_pairCommon(context, block) : enumeratorizeWithSize(context, this, "each", enumSizeFn());
    }

    public IRubyObject each19(final ThreadContext context, final Block block) {
        return each(context, block);
    }

    /** rb_hash_each_pair
     *
     */
    public RubyHash each_pairCommon(final ThreadContext context, final Block block) {
        iteratorVisitAll(context, YieldKeyValueArrayVisitor, block);

        return this;
    }

    private static final VisitorWithState<Block> YieldKeyValueArrayVisitor = new VisitorWithState<Block>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, Block block) {
            block.yield(context, context.runtime.newArray(key, value));
        }
    };

    /** rb_hash_each_value
     *
     */
    public RubyHash each_valueCommon(final ThreadContext context, final Block block) {
        iteratorVisitAll(context, YieldValueVisitor, block);

        return this;
    }

    private static final VisitorWithState<Block> YieldValueVisitor = new VisitorWithState<Block>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, Block block) {
            block.yield(context, value);
        }
    };

    @JRubyMethod
    public IRubyObject each_value(final ThreadContext context, final Block block) {
        return block.isGiven() ? each_valueCommon(context, block) : enumeratorizeWithSize(context, this, "each_value", enumSizeFn());
    }

    /** rb_hash_each_key
     *
     */
    public RubyHash each_keyCommon(final ThreadContext context, final Block block) {
        iteratorVisitAll(context, YieldKeyVisitor, block);

        return this;
    }

    private static final VisitorWithState<Block> YieldKeyVisitor = new VisitorWithState<Block>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, Block block) {
            block.yield(context, key);
        }
    };

    @JRubyMethod
    public IRubyObject each_key(final ThreadContext context, final Block block) {
        return block.isGiven() ? each_keyCommon(context, block) : enumeratorizeWithSize(context, this, "each_key", enumSizeFn());
    }

    @JRubyMethod(name = "transform_keys")
    public IRubyObject transform_keys(final ThreadContext context, final Block block) {
        if (block.isGiven()) {
            RubyHash result = newHash(context.runtime);
            visitAll(context, new TransformKeysVisitor(block), result);
            return result;
        }

        return enumeratorizeWithSize(context, this, "transform_keys", enumSizeFn());
    }

    private static class TransformKeysVisitor extends VisitorWithState<RubyHash> {
        private final Block block;

        public TransformKeysVisitor(Block block) {
            this.block = block;
        }

        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, RubyHash result) {
            IRubyObject newKey = block.yield(context, key);
            result.fastASet(newKey, value);
        }
    }

    @JRubyMethod(name = "transform_values")
    public IRubyObject transform_values(final ThreadContext context, final Block block) {
        return (new RubyHash(context.runtime, context.runtime.getHash(), this)).transform_values_bang(context, block);
    }

    @JRubyMethod(name = "transform_keys!")
    public IRubyObject transform_keys_bang(final ThreadContext context, final Block block) {
        if (block.isGiven()) {
            testFrozen("Hash");
            RubyArray pairs = (RubyArray) flatten(context);
            clear();
            for (int i = 0; i < pairs.size(); i += 2) {
                IRubyObject key = pairs.eltOk(i);
                IRubyObject newKey = block.yield(context, key);
                IRubyObject value = pairs.eltOk(i + 1);
                op_aset(context, newKey, value);
            }
            return this;
        }

        return enumeratorizeWithSize(context, this, "transform_keys!", enumSizeFn());
    }

    @JRubyMethod(name = "transform_values!")
    public IRubyObject transform_values_bang(final ThreadContext context, final Block block) {
        if (block.isGiven()) {
            testFrozen("Hash");
            TransformValuesVisitor tvf = new TransformValuesVisitor();
            iteratorVisitAll(context, tvf, block);
            return this;
        }

        return enumeratorizeWithSize(context, this, "transform_values!", enumSizeFn());
    }

    private static class TransformValuesVisitor extends VisitorWithState<Block> {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, Block block) {
            IRubyObject newValue = block.yield(context, value);
            self.op_aset(context, key, newValue);
        }
    }

    @JRubyMethod(name = "select!")
    public IRubyObject select_bang(final ThreadContext context, final Block block) {
        if (block.isGiven()) return keep_ifCommon(context, block) ? this : context.nil;

        return enumeratorizeWithSize(context, this, "select!", enumSizeFn());
    }

    @JRubyMethod
    public IRubyObject keep_if(final ThreadContext context, final Block block) {
        if (block.isGiven()) {
            keep_ifCommon(context, block);
            return this;
        }

        return enumeratorizeWithSize(context, this, "keep_if", enumSizeFn());
    }

    public boolean keep_ifCommon(final ThreadContext context, final Block block) {
        testFrozen("Hash");
        KeepIfVisitor kif = new KeepIfVisitor();
        iteratorVisitAll(context, kif, block);
        return kif.modified;
    }

    private static class KeepIfVisitor extends VisitorWithState<Block> {
        boolean modified = false;
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, Block block) {
            if (!block.yieldArray(context, context.runtime.newArray(key, value), null).isTrue()) {
                modified = true;
                self.remove(key);
            }
        }
    }

    @Deprecated
    public IRubyObject sort(ThreadContext context, Block block) {
        return to_a(context).sort_bang(context, block);
    }

    /** rb_hash_index
     *
     */
    @JRubyMethod(name = "index")
    public IRubyObject index(ThreadContext context, IRubyObject expected) {
        context.runtime.getWarnings().warn(ID.DEPRECATED_METHOD, "Hash#index is deprecated; use Hash#key");
        return key(context, expected);
    }

    @Deprecated
    public IRubyObject index19(ThreadContext context, IRubyObject expected) {
        return index(context, expected);
    }

    @JRubyMethod
    public IRubyObject key(ThreadContext context, IRubyObject expected) {
        IRubyObject key = internalIndex(context, expected);
        return key != null ? key : context.nil;
    }

    private IRubyObject internalIndex(final ThreadContext context, final IRubyObject expected) {
        try {
            visitAll(context, FoundKeyIfEqual, expected);
            return null;
        } catch (FoundKey found) {
            return found.key;
        }
    }

    private static final VisitorWithState<IRubyObject> FoundKeyIfEqual = new VisitorWithState<IRubyObject>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, IRubyObject expected) {
            if (equalInternal(context, value, expected)) {
                throw new FoundKey(key);
            }
        }
    };

    /** rb_hash_keys
     *
     */

    @JRubyMethod(name = "keys")
    public RubyArray keys(final ThreadContext context) {
        try {
            RubyArray keys = RubyArray.newBlankArrayInternal(context.runtime, size);

            visitAll(context, StoreKeyVisitor, keys);

            return keys;
        } catch (NegativeArraySizeException nase) {
            throw concurrentModification();
        }
    }

    public final RubyArray keys() {
        return keys(metaClass.runtime.getCurrentContext());
    }

    private static final VisitorWithState<RubyArray> StoreKeyVisitor = new VisitorWithState<RubyArray>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, RubyArray keys) {
            keys.storeInternal(index, key);
        }
    };

    /** rb_hash_values
     *
     */

    @JRubyMethod(name = "values")
    public RubyArray values(final ThreadContext context) {
        try {
            RubyArray values = RubyArray.newBlankArrayInternal(context.runtime, size);

            visitAll(context, StoreValueVisitor, values);

            return values;
        } catch (NegativeArraySizeException nase) {
            throw concurrentModification();
        }
    }

    public final RubyArray rb_values(ThreadContext context) {
        return values(context);
    }

    public static final VisitorWithState<RubyArray> StoreValueVisitor = new VisitorWithState<RubyArray>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, RubyArray values) {
            values.storeInternal(index, value);
        }
    };

    // like RubyHash.StoreValueVisitor but 'unsafe' - user needs to assure array capacity and adjust length
    static final VisitorWithState SetValueVisitor = new VisitorWithState<RubyArray>() {
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject val, int index, RubyArray target) {
            target.eltInternalSet(index, val);
        }
    };

    /** rb_hash_equal
     *
     */

    private static class Mismatch extends RuntimeException {
        public Throwable fillInStackTrace() {
            return this;
        }
    }
    private static final Mismatch MISMATCH = new Mismatch();

    /** rb_hash_shift
     *
     */
    @JRubyMethod(name = "shift")
    public IRubyObject shift(ThreadContext context) {
        modify();

        IRubyObject shifted = super.shift(context);

        if (shifted != null) return shifted;

        if (isBuiltin("default")) return default_value_get(context, context.nil);

        return sites(context).default_.call(context, this, this, context.nil);
    }

    public final boolean fastDelete(IRubyObject key) {
        return internalDelete(key) != null;
    }

    /** rb_hash_delete
     *
     */
    @JRubyMethod
    public IRubyObject delete(ThreadContext context, IRubyObject key, Block block) {
        modify();

        final IRubyObject value = internalDelete(key);
        if (value != null) return value;

        if (block.isGiven()) return block.yield(context, key);
        return context.nil;
    }

    public IRubyObject delete(ThreadContext context, IRubyObject key) {
        return delete(context, key, Block.NULL_BLOCK);
    }

    /** rb_hash_select
     *
     */
    @JRubyMethod(name = "select")
    public IRubyObject select(final ThreadContext context, final Block block) {
        final Ruby runtime = context.runtime;
        if (!block.isGiven()) return enumeratorizeWithSize(context, this, "select", enumSizeFn());

        final RubyHash result = newHash(runtime);

        iteratorVisitAll(context, new SelectVisitor(result), block);

        return result;
    }


    /** rb_hash_slice
     *
     */
    @JRubyMethod(name = "slice", rest = true)
    public RubyHash slice(final ThreadContext context, final IRubyObject[] args) {
        RubyHash result = newHash(context.runtime);

        for (int i = 0; i < args.length; i++) {
            IRubyObject key = args[i];
            IRubyObject value = this.internalGet(key);
            if (value != null) result.op_aset(key, value);
        }

        return result;
    }

    private static class SelectVisitor extends VisitorWithState<Block> {
        final RubyHash result;
        SelectVisitor(RubyHash result) {
            this.result = result;
        }

        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, Block block) {
            if (block.yieldArray(context, context.runtime.newArray(key, value), null).isTrue()) {
                result.fastASet(key, value);
            }
        }
    }

    @Deprecated
    public IRubyObject select19(ThreadContext context, Block block) {
        return select(context, block);
    }

    /** rb_hash_delete_if
     *
     */
    public RubyHash delete_ifInternal(ThreadContext context, Block block) {
        modify();

        iteratorVisitAll(context, DeleteIfVisitor, block);

        return this;
    }

    private static final VisitorWithState<Block> DeleteIfVisitor = new VisitorWithState<Block>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, Block block) {
            if (block.yieldArray(context, RubyArray.newArray(context.runtime, key, value), null).isTrue()) {
                self.delete(context, key, Block.NULL_BLOCK);
            }
        }
    };

    @JRubyMethod
    public IRubyObject delete_if(final ThreadContext context, final Block block) {
        return block.isGiven() ? delete_ifInternal(context, block) : enumeratorizeWithSize(context, this, "delete_if", enumSizeFn());
    }

    private static final class RejectVisitor extends VisitorWithState<Block> {
        final RubyHash result;
        RejectVisitor(RubyHash result) {
            this.result = result;
        }

        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, Block block) {
            if (!block.yieldArray(context, RubyArray.newArray(context.runtime, key, value), null).isTrue()) {
                result.fastASet(key, value);
            }
        }
    }

    /** rb_hash_reject
     *
     */
    public RubyHash rejectInternal(ThreadContext context, Block block) {
        final RubyHash result = newHash(context.runtime);

        iteratorVisitAll(context, new RejectVisitor(result), block);

        return result;
    }

    @JRubyMethod
    public IRubyObject reject(final ThreadContext context, final Block block) {
        return block.isGiven() ? rejectInternal(context, block) : enumeratorizeWithSize(context, this, "reject", enumSizeFn());
    }

    /** rb_hash_reject_bang
     *
     */
    public IRubyObject reject_bangInternal(ThreadContext context, Block block) {

        int n = this.size;
        delete_if(context, block);
        if (n == this.size) return context.nil;
        return this;
    }

    @JRubyMethod(name = "reject!")
    public IRubyObject reject_bang(final ThreadContext context, final Block block) {
        return block.isGiven() ? reject_bangInternal(context, block) : enumeratorizeWithSize(context, this, "reject!", enumSizeFn());
    }

    /** rb_hash_clear
     *
     */
    @JRubyMethod(name = "clear")
    public RubyHash rb_clear(ThreadContext context) {
        modify();

        clearAll();

        return this;
    }

    /** rb_hash_invert
     *
     */
    @JRubyMethod(name = "invert")
    public RubyHash invert(final ThreadContext context) {
        final RubyHash result = newHash(metaClass.runtime);

        visitAll(context, InvertVisitor, result);

        return result;
    }

    private static final VisitorWithState<RubyHash> InvertVisitor = new VisitorWithState<RubyHash>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, RubyHash state) {
            state.op_aset(context, value, key);
        }
    };

    /** rb_hash_update
     *
     */
    @JRubyMethod(name = {"merge!", "update"}, required = 1)
    public RubyHash merge_bang(ThreadContext context, IRubyObject other, Block block) {
        modify();
        final RubyHash otherHash = other.convertToHash();

        if (otherHash.empty_p(context).isTrue()) return this;

        otherHash.visitAll(context, new MergeVisitor(this), block);

        return this;
    }

    private static class MergeVisitor extends VisitorWithState<Block> {
        final RubyHash target;
        MergeVisitor(RubyHash target) {
            this.target = target;
        }
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, Block block) {
            if (block.isGiven()) {
                IRubyObject existing = target.internalGet(key);
                if (existing != null) {
                    value = block.yield(context, RubyArray.newArray(context.runtime, key, existing, value));
                }
            }
            target.op_aset(context, key, value);
        }
    };

    @Deprecated
    public RubyHash merge_bang19(ThreadContext context, IRubyObject other, Block block) {
        return merge_bang(context, other, block);
    }

    /** rb_hash_merge
     *
     */
    @JRubyMethod
    public RubyHash merge(ThreadContext context, IRubyObject other, Block block) {
        return ((RubyHash)dup()).merge_bang(context, other, block);
    }

    @JRubyMethod(name = "initialize_copy", required = 1, visibility = PRIVATE)
    public RubyHash initialize_copy(ThreadContext context, IRubyObject other) {
        return replace(context, other);
    }

    @Deprecated
    public RubyHash initialize_copy19(ThreadContext context, IRubyObject other) {
        return initialize_copy(context, other);
    }

    /** rb_hash_replace
     *
     */
    @JRubyMethod(name = "replace", required = 1)
    public RubyHash replace(final ThreadContext context, IRubyObject other) {
        modify();

        final RubyHash otherHash = other.convertToHash();

        if (this == otherHash) return this;

        rb_clear(context);

        if (!isComparedByIdentity() && otherHash.isComparedByIdentity()) {
            setComparedByIdentity(true);
        }

        otherHash.visitAll(context, ReplaceVisitor, this);

        ifNone = otherHash.ifNone;

        if ((otherHash.flags & PROCDEFAULT_HASH_F) != 0) {
            flags |= PROCDEFAULT_HASH_F;
        } else {
            flags &= ~PROCDEFAULT_HASH_F;
        }

        return this;
    }

    private static final VisitorWithState<RubyHash> ReplaceVisitor = new VisitorWithState<RubyHash>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, RubyHash target) {
            target.op_aset(context, key, value);
        }
    };

    /** rb_hash_values_at
     *
     */
    @JRubyMethod(name = "values_at", rest = true)
    public RubyArray values_at(ThreadContext context, IRubyObject[] args) {
        RubyArray result = RubyArray.newBlankArrayInternal(context.runtime, args.length);
        for (int i = 0; i < args.length; i++) {
            result.storeInternal(i, op_aref(context, args[i]));
        }
        return result;
    }

    @JRubyMethod(name = "fetch_values", rest = true)
    public RubyArray fetch_values(ThreadContext context, IRubyObject[] args, Block block) {
        RubyArray result = RubyArray.newBlankArrayInternal(context.runtime, args.length);
        for (int i = 0; i < args.length; i++) {
            result.storeInternal(i, fetch(context, args[i], block));
        }
        return result;
    }

    @JRubyMethod(name = "assoc")
    public IRubyObject assoc(final ThreadContext context, final IRubyObject obj) {
        try {
            visitAll(context, FoundPairIfEqualKeyVisitor, obj);
            return context.nil;
        } catch (FoundPair found) {
            return context.runtime.newArray(found.key, found.value);
        }
    }

    @JRubyMethod(name = "rassoc")
    public IRubyObject rassoc(final ThreadContext context, final IRubyObject obj) {
        try {
            visitAll(context, FoundPairIfEqualValueVisitor, obj);
            return context.nil;
        } catch (FoundPair found) {
            return context.runtime.newArray(found.key, found.value);
        }
    }

    private static final VisitorWithState<IRubyObject> FoundPairIfEqualKeyVisitor = new VisitorWithState<IRubyObject>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, IRubyObject obj) {
            if (equalInternal(context, obj, key)) {
                throw new FoundPair(key, value);
            }
        }
    };

    private static final VisitorWithState<IRubyObject> FoundPairIfEqualValueVisitor = new VisitorWithState<IRubyObject>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, IRubyObject obj) {
            if (equalInternal(context, obj, value)) {
                throw new FoundPair(key, value);
            }
        }
    };

    @JRubyMethod
    public IRubyObject flatten(ThreadContext context) {
        RubyArray ary = to_a(context);
        sites(context).flatten_bang.call(context, ary, ary, RubyFixnum.one(context.runtime));
        return ary;
    }

    @JRubyMethod
    public IRubyObject flatten(ThreadContext context, IRubyObject level) {
        RubyArray ary = to_a(context);
        sites(context).flatten_bang.call(context, ary, ary, level);
        return ary;
    }

    @JRubyMethod(name = "compact")
    public IRubyObject compact(ThreadContext context) {
      IRubyObject res = dup();
      ((RubyHash)res).compact_bang(context);
      return res;
    }

    @JRubyMethod(name = "compact!")
    public IRubyObject compact_bang(ThreadContext context) {
        boolean changed;
        modify();
        iteratorEntry();
        try {
            changed = compactEntries(context);
        } finally {
            iteratorExit();
        }
        return changed ? this : context.nil;
    }

    @JRubyMethod(name = "compare_by_identity")
    public IRubyObject compare_by_identity(ThreadContext context) {
        modify();
        setComparedByIdentity(true);
        return rehash(context);
    }

    @JRubyMethod(name = "compare_by_identity?")
    public IRubyObject compare_by_identity_p(ThreadContext context) {
        return context.runtime.newBoolean(isComparedByIdentity());
    }

    @JRubyMethod
    public IRubyObject dup(ThreadContext context) {
        RubyHash dup = (RubyHash) super.dup();
        dup.setComparedByIdentity(isComparedByIdentity());
        return dup;
    }

    @JRubyMethod(name = "clone")
    public IRubyObject rbClone(ThreadContext context) {
        RubyHash clone = (RubyHash) super.rbClone();
        clone.setComparedByIdentity(isComparedByIdentity());
        return clone;
    }

    @JRubyMethod(name = "any?", optional = 1)
    public IRubyObject any_p(ThreadContext context, IRubyObject[] args, Block block) {
        IRubyObject pattern = args.length > 0 ? args[0] : null;
        boolean patternGiven = pattern != null;

        if (isEmpty()) return context.fals;

        if (!block.isGiven() && !patternGiven) return context.tru;
        if (patternGiven) return anyPattern(context, pattern);

        if (block.getSignature().arityValue() > 1) {
            return anyIteratorFast(context, block);
        }
        return anyIterator(context, block);
    }

    /**
     * A lightweight dup for internal use that does not dispatch to initialize_copy nor rehash the keys. Intended for
     * use in dup'ing keyword args for processing.
     *
     * @param context
     * @return
     */
    public RubyHash dupFast(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        RubyHash dup = new RubyHash(runtime, metaClass, this);

        dup.setComparedByIdentity(this.isComparedByIdentity());

        dup.ifNone = this.ifNone;

        if ((this.flags & PROCDEFAULT_HASH_F) != 0) {
            dup.flags |= PROCDEFAULT_HASH_F;
        } else {
            dup.flags &= ~PROCDEFAULT_HASH_F;
        }

        return dup;
    }

    public boolean hasDefaultProc() {
        return (flags & PROCDEFAULT_HASH_F) != 0;
    }

    public IRubyObject getIfNone(){
        return ifNone;
    }

    @JRubyMethod(name = "dig", required = 1, rest = true)
    public IRubyObject dig(ThreadContext context, IRubyObject[] args) {
        return dig(context, args, 0);
    }

    final IRubyObject dig(ThreadContext context, IRubyObject[] args, int idx) {
        final IRubyObject val = op_aref( context, args[idx++] );
        return idx == args.length ? val : RubyObject.dig(context, val, args, idx);
    }

    @JRubyMethod
    public IRubyObject to_proc(ThreadContext context) {
        Block block = CallBlock19.newCallClosure(
                this,
                this.metaClass,
                Signature.ONE_ARGUMENT,
                (context1, args, procBlock) -> {
                    Arity.checkArgumentCount(context1, args, 1, 1);
                    return op_aref(context1, args[0]);
                },
                context);

        return RubyProc.newProc(context.runtime, block, Block.Type.PROC);
    }

    private static class VisitorIOException extends RuntimeException {
        VisitorIOException(Throwable cause) {
            super(cause);
        }
    }

    // FIXME:  Total hack to get flash in Rails marshalling/unmarshalling in session ok...We need
    // to totally change marshalling to work with overridden core classes.
    public static void marshalTo(final RubyHash hash, final MarshalStream output) throws IOException {
        output.registerLinkTarget(hash);
       int hashSize = hash.size;
       output.writeInt(hashSize);
        try {
            hash.visitLimited(hash.getRuntime().getCurrentContext(), MarshalDumpVisitor, hashSize, output);
        } catch (VisitorIOException e) {
            throw (IOException)e.getCause();
        }

        if (hash.ifNone != UNDEF) output.dumpObject(hash.ifNone);
    }

    private static final VisitorWithState<MarshalStream> MarshalDumpVisitor = new VisitorWithState<MarshalStream>() {
        @Override
        public void visit(ThreadContext context, RubyHash self, IRubyObject key, IRubyObject value, int index, MarshalStream output) {
            try {
                output.dumpObject(key);
                output.dumpObject(value);
            } catch (IOException e) {
                throw new VisitorIOException(e);
            }
        }
    };

    public static RubyHash unmarshalFrom(UnmarshalStream input, boolean defaultValue) throws IOException {
        RubyHash result = newHash(input.getRuntime());
        input.registerLinkTarget(result);
        int size = input.unmarshalInt();
        for (int i = 0; i < size; i++) {
            result.fastASetCheckString(input.getRuntime(), input.unmarshalObject(), input.unmarshalObject());
        }
        if (defaultValue) result.default_value_set(input.unmarshalObject());
        return result;
    }

    @Override
    public Class getJavaClass() {
        return Map.class;
    }

    // Satisfy java.util.Map interface (for Java integration)

    @Override
    public int size() {
        return size;
    }

    @Override
    public boolean isEmpty() {
        return size == 0;
    }

    @Override
    public boolean containsKey(Object key) {
        return internalGet(JavaUtil.convertJavaToUsableRubyObject(metaClass.runtime, key)) != null;
    }

    @Override
    public boolean containsValue(Object value) {
        return hasValue(metaClass.runtime.getCurrentContext(), JavaUtil.convertJavaToUsableRubyObject(metaClass.runtime, value));
    }

    @Override
    public Object get(Object key) {
        IRubyObject gotten = internalGet(JavaUtil.convertJavaToUsableRubyObject(metaClass.runtime, key));
        return gotten == null ? null : gotten.toJava(Object.class);
    }

    @Override
    public Object put(Object key, Object value) {
        Ruby runtime = metaClass.runtime;
        IRubyObject existing = internalJavaPut(JavaUtil.convertJavaToUsableRubyObject(runtime, key), JavaUtil.convertJavaToUsableRubyObject(runtime, value));
        return existing == null ? null : existing.toJava(Object.class);
    }

    @Override
    public Object remove(Object key) {
        IRubyObject rubyKey = JavaUtil.convertJavaToUsableRubyObject(metaClass.runtime, key);
        return internalDelete(rubyKey);
    }

    @Override
    public void putAll(Map map) {
        final Ruby runtime = metaClass.runtime;
        @SuppressWarnings("unchecked")
        final Iterator<Map.Entry> iter = map.entrySet().iterator();
        while ( iter.hasNext() ) {
            Map.Entry entry = iter.next();
            internalPut(
                JavaUtil.convertJavaToUsableRubyObject(runtime, entry.getKey()),
                JavaUtil.convertJavaToUsableRubyObject(runtime, entry.getValue())
            );
        }
    }

    @Override
    public void clear() {
        rb_clear(getRuntime().getCurrentContext());
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof RubyHash)) return false;
        if (this == other) return true;
        return op_equal(metaClass.runtime.getCurrentContext(), (RubyHash)other).isTrue();
    }

    @Override
    public Set keySet() {
        return new BaseSet(KEY_VIEW);
    }

    public Set directKeySet() {
        return new BaseSet(DIRECT_KEY_VIEW);
    }

    @Override
    public Collection values() {
        return new BaseCollection(VALUE_VIEW);
    }

    public Collection directValues() {
        return new BaseCollection(DIRECT_VALUE_VIEW);
    }

    @Override
    public Set entrySet() {
        return new BaseSet(ENTRY_VIEW);
    }

    public Set directEntrySet() {
        return new BaseSet(DIRECT_ENTRY_VIEW);
    }

    protected final RaiseException concurrentModification() {
        return metaClass.runtime.newConcurrencyError(
                "Detected invalid hash contents due to unsynchronized modifications with concurrent users");
    }

    /**
     * Is this object compared by identity or not? Shortcut for doing
     * getFlag(COMPARE_BY_IDENTITY_F).
     *
     * @return true if this object is compared by identity, false otherwise
     */
    protected boolean isComparedByIdentity() {
        return (flags & COMPARE_BY_IDENTITY_F) != 0;
    }

    /**
     * Sets whether this object is compared by identity or not. Shortcut for doing
     * setFlag(COMPARE_BY_IDENTITY_F, frozen).
     *
     * @param comparedByIdentity should this object be compared by identity?
     */
    public void setComparedByIdentity(boolean comparedByIdentity) {
        if (comparedByIdentity) {
            flags |= COMPARE_BY_IDENTITY_F;
        } else {
            flags &= ~COMPARE_BY_IDENTITY_F;
        }
    }

    private class BaseSet extends AbstractSet {
        final EntryView view;

        public BaseSet(EntryView view) {
            this.view = view;
        }

        @Override
        public Iterator iterator() {
            return new BaseIterator(view);
        }

        @Override
        public boolean contains(Object o) {
            return view.contains(RubyHash.this, o);
        }

        @Override
        public void clear() {
            RubyHash.this.clear();
        }

        @Override
        public int size() {
            return RubyHash.this.size;
        }

        @Override
        public boolean remove(Object o) {
            return view.remove(RubyHash.this, o);
        }
    }

    private class BaseCollection extends AbstractCollection {
        final EntryView view;

        public BaseCollection(EntryView view) {
            this.view = view;
        }

        @Override
        public Iterator iterator() {
            return new BaseIterator(view);
        }

        @Override
        public boolean contains(Object o) {
            return view.contains(RubyHash.this, o);
        }

        @Override
        public void clear() {
            RubyHash.this.clear();
        }

        @Override
        public int size() {
            return RubyHash.this.size;
        }

        @Override
        public boolean remove(Object o) {
            return view.remove(RubyHash.this, o);
        }
    }

    private static final EntryView DIRECT_KEY_VIEW = new EntryView() {
        @Override
        public Object convertEntry(Ruby runtime, RubyHash hash, IRubyObject key, IRubyObject value) {
            return key;
        }
        @Override
        public boolean contains(RubyHash hash, Object o) {
            if (!(o instanceof IRubyObject)) return false;
            return hash.internalGet((IRubyObject)o) != null;
        }
        @Override
        public boolean remove(RubyHash hash, Object o) {
            if (!(o instanceof IRubyObject)) return false;
            return hash.internalDelete((IRubyObject)o) != null;
        }
    };

    private static final EntryView KEY_VIEW = new EntryView() {
        @Override
        public Object convertEntry(Ruby runtime, RubyHash hash, IRubyObject key, IRubyObject value) {
            return key.toJava(Object.class);
        }
        @Override
        public boolean contains(RubyHash hash, Object o) {
            return hash.containsKey(o);
        }
        @Override
        public boolean remove(RubyHash hash, Object o) {
            return hash.remove(o) != null;
        }
    };

    private static final EntryView DIRECT_VALUE_VIEW = new EntryView() {
        @Override
        public Object convertEntry(Ruby runtime, RubyHash hash, IRubyObject key, IRubyObject value) {
            return value;
        }
        @Override
        public boolean contains(RubyHash hash, Object o) {
            if (!(o instanceof IRubyObject)) return false;
            IRubyObject obj = (IRubyObject)o;
            return hash.hasValue(obj.getRuntime().getCurrentContext(), obj);
        }
        @Override
        public boolean remove(RubyHash hash, Object o) {
            if (!(o instanceof IRubyObject)) return false;
            IRubyObject obj = (IRubyObject) o;
            IRubyObject key = hash.internalIndex(obj.getRuntime().getCurrentContext(), obj);
            if (key == null) return false;
            return hash.internalDelete(key) != null;
        }
    };

    private static final EntryView VALUE_VIEW = new EntryView() {
        @Override
        public Object convertEntry(Ruby runtime, RubyHash hash, IRubyObject key, IRubyObject value) {
            return value.toJava(Object.class);
        }
        @Override
        public boolean contains(RubyHash hash, Object o) {
            return hash.containsValue(o);
        }
        @Override
        public boolean remove(RubyHash hash, Object o) {
            Ruby runtime = hash.metaClass.runtime;
            IRubyObject value = JavaUtil.convertJavaToUsableRubyObject(runtime, o);
            IRubyObject key = hash.internalIndex(runtime.getCurrentContext(), value);
            if (key == null) return false;
            return hash.internalDelete(key) != null;
        }
    };

    private static final EntryView DIRECT_ENTRY_VIEW = new EntryView() {
        @Override
        public Object convertEntry(Ruby runtime, RubyHash hash, IRubyObject key, IRubyObject value) {
            return new RubyHashEntry(key, value);
        }
        @Override
        public boolean contains(RubyHash hash, Object o) {
            if (!(o instanceof RubyHashEntry)) return false;
            RubyHashEntry entry = (RubyHashEntry)o;
            RubyHashEntry candidate = hash.internalGetEntry(entry.key);
            return candidate != NO_ENTRY && entry.equals(candidate);
        }
        @Override
        public boolean remove(RubyHash hash, Object o) {
            if (!(o instanceof RubyHashEntry)) return false;
            RubyHashEntry candidate = (RubyHashEntry)o;
            return hash.internalDeleteEntry(candidate.key, candidate.value) != null;
        }
    };

    private static final EntryView ENTRY_VIEW = new EntryView() {
        @Override
        public Object convertEntry(Ruby runtime, RubyHash hash, IRubyObject key, IRubyObject value) {
            return new ConvertingEntry(runtime, hash, key, value);
        }
        @Override
        public boolean contains(RubyHash hash, Object o) {
            if (!(o instanceof ConvertingEntry)) return false;
            ConvertingEntry entry = (ConvertingEntry)o;
            RubyHashEntry tmp = new RubyHashEntry(entry.key, entry.value);
            RubyHashEntry candidate = hash.internalGetEntry(entry.key);
            return candidate != NO_ENTRY && tmp.equals(candidate);
        }
        @Override
        public boolean remove(RubyHash hash, Object o) {
            if (!(o instanceof ConvertingEntry)) return false;
            ConvertingEntry entry = (ConvertingEntry)o;
            return hash.internalDeleteEntry(entry.key, entry.value) != null;
        }
    };

    private static class ConvertingEntry implements Map.Entry {
        private final IRubyObject key, value;
        private final Ruby runtime;
        private RubyHash hash;

        public ConvertingEntry(Ruby runtime, RubyHash otherHash, IRubyObject key, IRubyObject value) {
            this.key = key;
            this.value = value;
            this.runtime = runtime;
            this.hash = otherHash;
        }

        @Override
        public Object getKey() {
            return key.toJava(Object.class);
        }
        @Override
        public Object getValue() {
            return value.toJava(Object.class);
        }
        @Override
        public Object setValue(Object o) {
            IRubyObject value = JavaUtil.convertJavaToUsableRubyObject(runtime, o);
            return hash.internalPut(key, value);
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof ConvertingEntry)) {
                return false;
            }
            ConvertingEntry otherEntry = (ConvertingEntry)o;
            return (key == otherEntry.key || key.eql(otherEntry.key)) &&
                    (value == otherEntry.value || value.equals(otherEntry.value));
        }

        @Override
        public int hashCode() {
            return key.hashCode() ^ value.hashCode();
        }
    }

    @Deprecated
    public IRubyObject op_aset19(ThreadContext context, IRubyObject key, IRubyObject value) {
        modify();

        fastASetCheckString19(context.runtime, key, value);
        return value;
    }

    /**
     * Note: this is included as a compatibility measure for AR-JDBC
     * @deprecated use RubyHash.op_aset instead
     */
    public IRubyObject aset(IRubyObject key, IRubyObject value) {
        return op_aset(metaClass.runtime.getCurrentContext(), key, value);
    }

    /**
     * Note: this is included as a compatibility measure for Mongrel+JRuby
     * @deprecated use RubyHash.op_aref instead
     */
    public IRubyObject aref(IRubyObject key) {
        return op_aref(metaClass.runtime.getCurrentContext(), key);
    }

    private static HashSites sites(ThreadContext context) {
        return context.sites.Hash;
    }

    @Deprecated
    public final void fastASetCheckString19(Ruby runtime, IRubyObject key, IRubyObject value) {
        fastASetCheckString(runtime, key, value);
    }

    @Deprecated
    public IRubyObject op_aset(IRubyObject key, IRubyObject value) {
        return op_aset(metaClass.runtime.getCurrentContext(), key, value);
    }

    @Deprecated
    public IRubyObject each_pair(final ThreadContext context, final Block block) {
        return block.isGiven() ? each_pairCommon(context, block) : enumeratorizeWithSize(context, this, "each_pair", enumSizeFn());
    }

    @Deprecated
    public RubyHash each_pairCommon(final ThreadContext context, final Block block, final boolean oneNine) {
        iteratorVisitAll(context, YieldKeyValueArrayVisitor, block);

        return this;
    }

    @Deprecated
    public RubyHash replace19(final ThreadContext context, IRubyObject other) {
        return replace(context, other);
    }

    @Deprecated
    public final void visitAll(Visitor visitor) {
        // use -1 to disable concurrency checks
        visitLimited(getRuntime().getCurrentContext(), visitor, -1, null);
    }

    /** rb_hash_default
     *
     */
    @Deprecated
    public IRubyObject default_value_get(ThreadContext context, IRubyObject[] args) {
        switch (args.length) {
            case 0: return default_value_get(context);
            case 1: return default_value_get(context, args[0]);
            default:
                throw context.runtime.newArgumentError(args.length, 1);
        }
    }

    @Deprecated
    protected void internalPutSmall(final IRubyObject key, final IRubyObject value, final boolean checkForExisting) {
        internalPut(key, value);
    }

    @Deprecated
    @Override
    public RubyArray to_a() {
        return to_a(getRuntime().getCurrentContext());
    }

    @Deprecated
    public IRubyObject default_value_set(final IRubyObject defaultValue) {
        return default_value_set(getRuntime().getCurrentContext(), defaultValue);
    }

    @Deprecated
    public IRubyObject default_proc() {
        return (flags & PROCDEFAULT_HASH_F) != 0 ? ifNone : metaClass.runtime.getNil();
    }

    @Deprecated
    public IRubyObject set_default_proc(IRubyObject proc) {
        return set_default_proc(getRuntime().getCurrentContext(), proc);
    }

    @Deprecated
    public IRubyObject set_default_proc20(IRubyObject proc) {
        return set_default_proc(proc);
    }

    @Deprecated
    public RubyFixnum rb_size() {
        return metaClass.runtime.newFixnum(size);
    }

    @Deprecated
    public RubyBoolean empty_p() {
        return size == 0 ? metaClass.runtime.getTrue() : metaClass.runtime.getFalse();
    }

    @Deprecated
    public RubyHash rehash() {
        return rehash(getRuntime().getCurrentContext());
    }

    @Deprecated
    public RubyHash to_hash() {
        return to_hash(getRuntime().getCurrentContext());
    }

    @Deprecated
    public final RubyArray rb_values() {
        return values(metaClass.runtime.getCurrentContext());
    }

    @Deprecated
    public RubyHash rb_clear() {
        return rb_clear(getRuntime().getCurrentContext());
    }
}

package org.jruby.hash;

import org.jruby.RubyString;
import org.jruby.runtime.builtin.IRubyObject;

public interface HashStrategy {
    IRubyObject put(HashImpl self, IRubyObject key, int hash, IRubyObject value);

    void putDirect(HashImpl self, IRubyObject key, int hash, IRubyObject value);

    IRubyObject get(HashImpl self, IRubyObject key, int hash);

    void putString(HashImpl self, RubyString key, int hash, IRubyObject value);

    void rehash(HashImpl self);

    IRubyObject delete(HashImpl self, HashImpl.EntryMatchType matchType, IRubyObject key, int hash, IRubyObject value);

    void copy(HashImpl self, HashImpl target);

    void alloc(HashImpl self, int buckets);

    void resize(HashImpl self, int newCapacity);
}

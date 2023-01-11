package org.jruby.runtime.callsite;

import org.jruby.RubyClass;
import org.jruby.internal.runtime.methods.DynamicMethod;
import org.jruby.ir.IRScope;
import org.jruby.parser.StaticScope;
import org.jruby.runtime.Block;
import org.jruby.runtime.CallType;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

public class RefinedCachingCallSite extends CachingCallSite {
    private final StaticScope scope;

    public RefinedCachingCallSite(String methodName, StaticScope scope, CallType callType) {
        super(methodName, callType);

        this.scope = scope;
    }

    public RefinedCachingCallSite(String methodName, IRScope scope, CallType callType) {
        this(methodName, scope.getStaticScope(), callType);
    }

    @Override
    protected IRubyObject cacheAndCall(IRubyObject caller, RubyClass selfType, IRubyObject[] args, ThreadContext context, IRubyObject self) {
        CacheEntry entry = selfType.searchWithRefinements(methodName, scope);
        DynamicMethod method = entry.method;

        if (methodMissing(method, caller)) {
            return callMethodMissing(context, self, selfType, method, args);
        }

        entry = setCache(entry, self);

        return method.call(context, self, entry.sourceModule, methodName, args);
    }

    @Override
    protected IRubyObject cacheAndCall(IRubyObject caller, RubyClass selfType, Block block, IRubyObject[] args, ThreadContext context, IRubyObject self) {
        CacheEntry entry = selfType.searchWithRefinements(methodName, scope);
        DynamicMethod method = entry.method;

        if (methodMissing(method, caller)) {
            return callMethodMissing(context, self, selfType, method, args, block);
        }

        entry = setCache(entry, self);

        return method.call(context, self, entry.sourceModule, methodName, args, block);
    }

    @Override
    protected IRubyObject cacheAndCall(IRubyObject caller, RubyClass selfType, ThreadContext context, IRubyObject self) {
        CacheEntry entry = selfType.searchWithRefinements(methodName, scope);
        DynamicMethod method = entry.method;

        if (methodMissing(method, caller)) {
            return callMethodMissing(context, self, selfType, method);
        }

        entry = setCache(entry, self);

        return method.call(context, self, entry.sourceModule, methodName);
    }

    @Override
    protected IRubyObject cacheAndCall(IRubyObject caller, RubyClass selfType, Block block, ThreadContext context, IRubyObject self) {
        CacheEntry entry = selfType.searchWithRefinements(methodName, scope);
        DynamicMethod method = entry.method;

        if (methodMissing(method, caller)) {
            return callMethodMissing(context, self, selfType, method, block);
        }

        entry = setCache(entry, self);

        return method.call(context, self, entry.sourceModule, methodName, block);
    }


    @Override
    protected IRubyObject cacheAndCall(IRubyObject caller, RubyClass selfType, ThreadContext context, IRubyObject self, IRubyObject arg0) {
        CacheEntry entry = selfType.searchWithRefinements(methodName, scope);
        DynamicMethod method = entry.method;

        if (methodMissing(method, caller)) {
            return callMethodMissing(context, self, selfType, method, arg0);
        }

        entry = setCache(entry, self);

        return method.call(context, self, entry.sourceModule, methodName, arg0);
    }

    @Override
    protected IRubyObject cacheAndCall(IRubyObject caller, RubyClass selfType, Block block, ThreadContext context, IRubyObject self, IRubyObject arg0) {
        CacheEntry entry = selfType.searchWithRefinements(methodName, scope);
        DynamicMethod method = entry.method;

        if (methodMissing(method, caller)) {
            return callMethodMissing(context, self, selfType, method, arg0, block);
        }

        entry = setCache(entry, self);

        return method.call(context, self, entry.sourceModule, methodName, arg0, block);
    }

    @Override
    protected IRubyObject cacheAndCall(IRubyObject caller, RubyClass selfType, ThreadContext context, IRubyObject self, IRubyObject arg0, IRubyObject arg1) {
        CacheEntry entry = selfType.searchWithRefinements(methodName, scope);
        DynamicMethod method = entry.method;

        if (methodMissing(method, caller)) {
            return callMethodMissing(context, self, selfType, method, arg0, arg1);
        }

        entry = setCache(entry, self);

        return method.call(context, self, entry.sourceModule, methodName, arg0, arg1);
    }

    @Override
    protected IRubyObject cacheAndCall(IRubyObject caller, RubyClass selfType, Block block, ThreadContext context, IRubyObject self, IRubyObject arg0, IRubyObject arg1) {
        CacheEntry entry = selfType.searchWithRefinements(methodName, scope);
        DynamicMethod method = entry.method;

        if (methodMissing(method, caller)) {
            return callMethodMissing(context, self, selfType, method, arg0, arg1, block);
        }

        entry = setCache(entry, self);

        return method.call(context, self, entry.sourceModule, methodName, arg0, arg1, block);
    }

    @Override
    protected IRubyObject cacheAndCall(IRubyObject caller, RubyClass selfType, ThreadContext context, IRubyObject self, IRubyObject arg0, IRubyObject arg1, IRubyObject arg2) {
        CacheEntry entry = selfType.searchWithRefinements(methodName, scope);
        DynamicMethod method = entry.method;

        if (methodMissing(method, caller)) {
            return callMethodMissing(context, self, selfType, method, arg0, arg1, arg2);
        }

        entry = setCache(entry, self);

        return method.call(context, self, entry.sourceModule, methodName, arg0, arg1, arg2);
    }

    @Override
    protected IRubyObject cacheAndCall(IRubyObject caller, RubyClass selfType, Block block, ThreadContext context, IRubyObject self, IRubyObject arg0, IRubyObject arg1, IRubyObject arg2) {
        CacheEntry entry = selfType.searchWithRefinements(methodName, scope);
        DynamicMethod method = entry.method;

        if (methodMissing(method, caller)) {
            return callMethodMissing(context, self, selfType, method, arg0, arg1, arg2, block);
        }

        entry = setCache(entry, self);

        return method.call(context, self, entry.sourceModule, methodName, arg0, arg1, arg2, block);
    }

    protected boolean methodMissing(DynamicMethod method, IRubyObject caller) {
        // doing full "normal" MM check rather than multiple refined sites by call types
        return method.isUndefined() || (!methodName.equals("method_missing") && !method.isCallableFrom(caller, callType));
    }
}

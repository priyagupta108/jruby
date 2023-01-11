package org.jruby.ir.targets.indy;

import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.ir.runtime.IRRuntimeHelpers;
import org.jruby.runtime.Block;
import org.jruby.runtime.CallType;
import org.jruby.runtime.Helpers;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.callsite.CacheEntry;

import java.lang.invoke.MethodType;

/**
* Created by headius on 10/23/14.
*/
public class ZSuperInvokeSite extends SuperInvokeSite {
    protected CacheEntry entry = CacheEntry.NULL_CACHE;

    public ZSuperInvokeSite(MethodType type, String name, String splatmapString, String file, int line) {
        super(type, name, splatmapString, file, line);
    }

    public IRubyObject invoke(ThreadContext context, IRubyObject caller, IRubyObject self, RubyClass definingModule, IRubyObject[] args, Block block) throws Throwable {
        // TODO: get rid of caller
        // TODO: caching
        if (block == null || !block.isGiven()) block = context.getFrameBlock();
        Block block1 = block;
        if (block1 == null || !block1.isGiven()) block1 = context.getFrameBlock();
        IRubyObject[] args1 = IRRuntimeHelpers.splatArguments(args, splatMap);
        // We have to rely on the frame stack to find the implementation class
        RubyModule klazz = context.getFrameKlazz();
        String methodName1 = context.getFrameName();

        Helpers.checkSuperDisabledOrOutOfMethod(context, klazz, methodName1);

        RubyClass superClass = IRRuntimeHelpers.searchNormalSuperclass(klazz);
        CacheEntry entry = this.entry;
        if (!entry.typeOk(superClass)) {
            this.entry = entry = superClass != null ? superClass.searchWithCache(methodName1) : CacheEntry.NULL_CACHE;
        }

        IRubyObject rVal;
        if (entry.method.isUndefined()) {
            rVal = Helpers.callMethodMissing(context, self, entry.method.getVisibility(), methodName1, CallType.SUPER, args1, block1);
        } else {
            rVal = entry.method.call(context, self, entry.sourceModule, methodName1, args1, block1);
        }

        return rVal;
    }

    public IRubyObject fail(ThreadContext context, IRubyObject caller, IRubyObject self, RubyClass definingModule, IRubyObject[] args, Block block) throws Throwable {
        return invoke(context, caller, self, definingModule, args, block);
    }
}

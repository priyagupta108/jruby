package org.jruby.ir.targets.indy;

import org.jruby.RubyClass;
import org.jruby.internal.runtime.methods.DynamicMethod;
import org.jruby.ir.runtime.IRRuntimeHelpers;
import org.jruby.java.invokers.InstanceMethodInvoker;
import org.jruby.java.proxies.JavaProxy;
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
public class InstanceSuperInvokeSite extends ResolvedSuperInvokeSite {
    public InstanceSuperInvokeSite(MethodType type, String name, String splatmapString, String file, int line) {
        super(type, name, splatmapString, file, line);
    }

    @Override
    protected RubyClass getSuperClass(RubyClass definingModule) {
        return definingModule.getSuperClass();
    }

    // FIXME: indy cached version was not doing splat mapping; revert to slow logic for now

    public IRubyObject invoke(ThreadContext context, IRubyObject caller, IRubyObject self, RubyClass definingModule, IRubyObject[] args, Block block) throws Throwable {
        IRubyObject[] args1 = IRRuntimeHelpers.splatArguments(args, splatMap);
        CacheEntry entry = this.entry;

        RubyClass superClass = definingModule.getMethodLocation().getSuperClass();
        if (!entry.typeOk(superClass)) {
            this.entry = entry = superClass != null ? superClass.searchWithCache(superName) : CacheEntry.NULL_CACHE;
        }
        DynamicMethod method = entry.method;

        if (method instanceof InstanceMethodInvoker && self instanceof JavaProxy) {
            return IRRuntimeHelpers.javaProxySuper(
                    context,
                    (JavaProxy) self,
                    superName,
                    (RubyClass) definingModule,
                    args1,
                    (InstanceMethodInvoker) method);
        }

        if (method.isUndefined()) {
            return Helpers.callMethodMissing(context, self, method.getVisibility(), superName, CallType.SUPER, args1, block);
        }

        return method.call(context, self, entry.sourceModule, superName, args1, block);
    }
}

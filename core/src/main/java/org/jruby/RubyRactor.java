/*
 **** BEGIN LICENSE BLOCK *****
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

import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.ast.util.ArgsUtil;
import org.jruby.ractor.Ractor;
import org.jruby.runtime.Block;
import org.jruby.runtime.BlockCallback;
import org.jruby.runtime.CallBlock;
import org.jruby.runtime.Helpers;
import org.jruby.runtime.Signature;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

import java.util.function.Consumer;

/**
 * Implementation of the Ractor class.
 */
@JRubyClass(name="Ractor")
public class RubyRactor extends RubyObject {
    private Ractor ractor;

    public static RubyClass createRactorClass(Ruby runtime) {
        RubyClass ractorClass = runtime.defineClass("Ractor", runtime.getObject(), RubyRactor::new);

        ractorClass.defineAnnotatedMethods(RubyRactor.class);

        return ractorClass;
    }

    public RubyRactor(Ruby runtime, RubyClass rubyClass) {
        super(runtime, rubyClass);
    }

    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize(ThreadContext context, Block block) {
        return initialize(context, context.nil, block);
    }

    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize(ThreadContext context, IRubyObject opts, Block block) {
        Ruby runtime = context.runtime;

        if (!block.isGiven()) runtime.newArgumentError("must be called with a block");

//        String name = ArgsUtil.extractKeywordArg(context, "name", opts).asJavaString();

        Consumer<Ractor> callback = (ractor) -> {
            IRubyObject result = block.call(ractor.ractorRuntime.getCurrentContext());

            try {
                ractor.putOutput(result);
            } catch (InterruptedException ie) {
                Helpers.throwException(ie);
            }
        };

        this.ractor = Ruby.newRactorInstance(callback);

        return context.nil;
    }

    @JRubyMethod
    public IRubyObject name(ThreadContext context) {
        return context.runtime.newString(ractor.name);
    }

    @JRubyMethod(name = {"send", "<<"})
    public IRubyObject send(ThreadContext context, IRubyObject object) throws InterruptedException {
        ractor.putInput(object);

        return context.nil;
    }

    @JRubyMethod
    public IRubyObject take (ThreadContext context) throws InterruptedException {
        return ractor.takeOutput();
    }

    @JRubyMethod(meta = true)
    public static IRubyObject yield(ThreadContext context, IRubyObject recv, IRubyObject object) throws InterruptedException {
        Ractor ractor = context.runtime.ractor;

        ractor.putOutput(object);

        return ractor.takeInput();
    }

    @JRubyMethod(meta = true)
    public static IRubyObject receive(ThreadContext context, IRubyObject recv) throws InterruptedException {
        Ractor ractor = context.runtime.ractor;

        return ractor.takeInput();
    }
}

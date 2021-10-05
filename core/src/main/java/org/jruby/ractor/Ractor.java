package org.jruby.ractor;

import org.jruby.Ruby;
import org.jruby.runtime.builtin.IRubyObject;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class Ractor {
    private final BlockingQueue<IRubyObject> output = new LinkedBlockingQueue<>();
    private final BlockingQueue<IRubyObject> input = new LinkedBlockingQueue<>();

    public final String name;
    public final Ruby ractorRuntime;

    public Ractor(Ruby runtime, String name) {
        this.ractorRuntime = runtime;
        this.name = name;
    }

    public IRubyObject takeInput() throws InterruptedException {
        return input.take();
    }

    public IRubyObject takeOutput() throws InterruptedException {
        return output.take();
    }

    public void putInput(IRubyObject object) throws InterruptedException {
        input.put(object);
    }

    public void putOutput(IRubyObject object) throws InterruptedException {
        output.put(object);
    }
}

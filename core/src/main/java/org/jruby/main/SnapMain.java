package org.jruby.main;

import org.jruby.Main;
import org.jruby.Ruby;
import org.jruby.RubyInstanceConfig;
import org.jruby.util.SafePropertyAccessor;
import org.jruby.util.cli.Options;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class SnapMain {
    public static final RubyInstanceConfig SNAP_CONFIG;
    public static final Ruby SNAP_RUNTIME;
    public static final boolean USE_SNAPSHOT_RUNTIME = SafePropertyAccessor.getBoolean("jruby.native.image", false);

    public static final String JRUBY_SNAP_WARMUP_ENV = "JRUBY_SNAP_WARMUP";
    public static final String JRUBY_SNAP_WARMUP_DEFAULT = "1 + 1";
    public static final String JRUBY_SNAP_PREBOOT_FILE = "./snapmain.rb";
    
    static {
        if (USE_SNAPSHOT_RUNTIME) {
            // warmup JVM first
            Ruby ruby = Ruby.newInstance();

            String envWarmup = System.getenv(JRUBY_SNAP_WARMUP_ENV);
            if (envWarmup != null && envWarmup.length() > 0) {
                ruby.evalScriptlet(envWarmup);
            } else {
                ruby.evalScriptlet(JRUBY_SNAP_WARMUP_DEFAULT);
            }

            // preboot actual runtime
            Ruby.clearGlobalRuntime();
            File snapMain = new File(JRUBY_SNAP_PREBOOT_FILE);

            RubyInstanceConfig config = new RubyInstanceConfig();
            ruby = Ruby.newInstance(config);

            if (snapMain.exists()) {
                try {
                    try (FileInputStream fis = new FileInputStream(snapMain)) {
                        ruby.loadFile(snapMain.getAbsolutePath(), fis, false);
                    }
                } catch (IOException ioe) {
                    throw new RuntimeException(ioe);
                }
            }

            // use config and runtime from preboot process after scrubbing out transient references
            ruby.getThreadService().teardown();

            SNAP_CONFIG = config;
            SNAP_RUNTIME = ruby;
        } else {
            SNAP_CONFIG = null;
            SNAP_RUNTIME = null;
        }
    }

    public static void main(String[] args) {
        Main.main(args);
    }
}

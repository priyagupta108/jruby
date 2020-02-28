require 'benchmark/ips'

Benchmark.ips do |ips|
  # Non-overloaded, defined on target class
  ips.report("100k ArrayList#java_method(:add)") do
    ary = java.util.ArrayList.new
    args = [java.lang.Object]
    i = 0
    while i < 100_000
      i+=1
      ary.java_method(:add, args)
    end
  end

  # Non-overloaded, defined on supertype
  ips.report("100k ArrayList#java_method(:isEmpty)") do
    ary = java.util.ArrayList.new
    i = 0
    while i < 100_000
      i+=1
      ary.java_method(:isEmpty)
    end
  end

  # Overloaded, defined on target class
  ips.report("100k StringBuffer#java_method(:append)") do
    ary = java.lang.StringBuffer.new
    args = [java.lang.Object]
    i = 0
    while i < 100_000
      i+=1
      ary.java_method(:append, args)
    end
  end
end
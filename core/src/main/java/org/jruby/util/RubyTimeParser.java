package org.jruby.util;

import org.jruby.RubyFixnum;
import org.jruby.RubyInteger;
import org.jruby.RubyRational;
import org.jruby.RubyString;
import org.jruby.RubyTime;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

import static org.jruby.api.Convert.*;
import static org.jruby.api.Convert.asFixnum;
import static org.jruby.api.Error.argumentError;
import static org.jruby.util.RubyStringBuilder.str;

public class RubyTimeParser {
    public static final int TIME_SCALE_NUMDIGITS = 10;
    public static final long SIZE_MAX = Long.MAX_VALUE;

    
    private int beg;
    private int ptr;
    private int end;
    private byte[] bytes;

    // This is a temporal value which individual parsing methods use but we just use a field because java out
    // params isn't much more appealing.
    private int ndigits;

    public IRubyObject parse(ThreadContext context, RubyTime self, RubyString str, IRubyObject zone, IRubyObject precision) {
        ByteList bytelist = str.getByteList();
        beg = bytelist.begin();
        ptr = beg;
        end = beg + bytelist.length();
        bytes = bytelist.unsafeBytes();
        ndigits = 0;

        IRubyObject year;
        IRubyObject subsec = context.nil;
        int mon = -1, mday = -1, hour = -1, min = -1, sec = -1;
        long prec = precision.isNil() ? SIZE_MAX : numericToLong(context, precision);

        if (!isEOS() && (isSpace() || Character.isSpaceChar(bytes[end - 1]))) {
            throw argumentError(context, str(context.runtime, "can't parse: ", str));
        }
        year = parseInt(context, true);
        if (year.isNil()) throw argumentError(context, str(context.runtime, "can't parse: ", str));
        if (ndigits < 4) {
            IRubyObject invalidYear = context.runtime.newString(new ByteList(bytes, ptr - ndigits - beg, ndigits, true));
            throw argumentError(context, str(context.runtime, "year must be 4 or more digits: ", invalidYear));
        }
        if (ptr == end) { // only year provided
            return self.initialize(context, year, context.nil, context.nil, context.nil, context.nil, context.nil, precision, zone);
        }
        do {
            if (peek() != '-') break;
            advance();
            mon = expectTwoDigits(context, "mon", 12);
            if (peek() != '-') break;
            advance();
            mday = expectTwoDigits(context, "mday", 31);
            byte next = peek();
            if (next != ' ' && next != 'T') break;
            advance();
            int timePart = ptr;
            if (1 >= end - ptr || !isDigit(0)) break;

            hour = expectTwoDigits(context, "hour", 24);
            noFraction(context, "hour", timePart);
            needColon(context, "min", timePart);
            min = expectTwoDigits(context, "min", 60);
            noFraction(context, "min", timePart);
            needColon(context, "sec", timePart);
            sec = expectTwoDigits(context, "sec", 60);
            if (peek() == '.') {
                advance();
                int digits;
                for (digits = 0; digits < prec; digits++) {
                    if (!isDigit(digits)) break;
                }
                if (digits == 0) {
                    // FIXME: some precise mbc for garbled time string
                    IRubyObject invalidSecs = context.runtime.newString(new ByteList(bytes, timePart, ptr - timePart + 1, true));
                    throw argumentError(context, str(context.runtime, "subsecond expected after dot: ", invalidSecs));
                }
                ndigits = digits;
                subsec = parseInt(context, false);
                if (subsec.isNil()) break;
                while (!isEOS() && isDigit(0)) ptr++;
            }
        } while (false);
        eatSpace();
        int zstr = ptr;
        while (!isEOS() && !isSpace()) advance();
        int zend = ptr;
        eatSpace();
        if (!isEOS()) {
            IRubyObject invalid = context.runtime.newString(new ByteList(bytes, ptr, end - ptr, true));
            throw argumentError(context, str(context.runtime, "can't parse at: ", invalid));
        }
        if (zend > zstr) {
            zone = context.runtime.newString(new ByteList(bytes, zstr, zend - zstr, true));
        } else if (hour == -1) {
            throw argumentError(context, "no time information");
        }
        if (!subsec.isNil()) {
            if (ndigits < TIME_SCALE_NUMDIGITS) {
                int mul = (int) Math.pow(10, TIME_SCALE_NUMDIGITS - ndigits);
                subsec = RubyFixnum.newFixnum(context.runtime, asLong(context, (RubyInteger) subsec) * mul);
            } else if (ndigits > TIME_SCALE_NUMDIGITS) {
                int mul = (int) Math.pow(10, ndigits - TIME_SCALE_NUMDIGITS);
                subsec = RubyRational.newRational(context.runtime, asLong(context, (RubyInteger) subsec), mul);
            }
        }

        return self.initialize(context, year, asFixnum(context, mon), asFixnum(context, mday), asFixnum(context, hour),
                asFixnum(context, min), asFixnum(context, sec), subsec, zone);
    }

    private void advance() {
        ptr++;
    }

    private void eatSpace() {
        while (!isEOS() && isSpace()) advance();
    }

    private byte peek() {
        return ptr < end ? bytes[ptr] : 0;
    }

    private byte peek(int offset) {
        int p = ptr + offset;
        return p < end ? bytes[p] : 0;
    }

    private boolean isEOS() {
        return ptr >= end;
    }

    private boolean isDigit(int offset) {
        return Character.isDigit(peek(offset));
    }

    private boolean isSpace() {
        return Character.isSpaceChar(peek());
    }

    private void needColon(ThreadContext context, String label, int start) {
        if (peek() != ':') {
            throw argumentError(context, str(context.runtime, "missing " + label + " part: ", substr(context, start)));
        }
        advance();
    }

    private void noFraction(ThreadContext context, String label, int start) {
        if (peek() == '.') {
            throw argumentError(context, str(context.runtime, "fraction " + label + " is not supported: ", substr(context, start)));
        }
    }

    private IRubyObject substr(ThreadContext context, int from) {
        return context.runtime.newString(new ByteList(bytes, from, ptr - from + 1, true));
    }

    private int twoDigits(ThreadContext context, String label) {
        int len = end - ptr;
        if (len < 2 || !(isDigit(0) && isDigit(1)) || (len > 2 && isDigit(2))) {
            StringBuilder builder = new StringBuilder("two digits ");
            builder.append(label).append(" is expected");
            byte pre = peek(-1);
            if (pre == '-' || pre == ':') builder.append(" after '").append((char) pre).append("'");

            builder.append(": ").append(new ByteList(bytes, ptr - 1, len > 10 ? 11 : len + 1, true));
            throw argumentError(context, builder.toString());
        }

        return (peek(0) - '0') * 10 + (peek(1) - '0');
    }

    private int expectTwoDigits(ThreadContext context, String label, int max) {
        int value = twoDigits(context, label);

        if (value > max) throw argumentError(context, "" + label + " out of range");

        advance(); advance();
        return value;
/*        int error = 0;
        int total = 0;

        if (isDigit(0) && isDigit(1)) {
            byte one = peek();
            advance();
            byte two = peek();
            advance();
            total = (one - '0') * 10 + (two - '0');
            if (isDigit(0)) { // extra digits
                error = 3;
            }
            if (error == 0 && total > max) throw argumentError(context, "" + label + " out of range");
        } else {
            if (!isDigit(1)) { // only one digit
                error = 1;
                advance();
            } else {
                advance(); // just to get error reporting consistent for error string.
                advance();
                if (isDigit(0)) { // extra digits
                    error = 3;
                } else {
                    error = 2;
                }
            }
        }

        if (error != 0) {
            StringBuilder builder = new StringBuilder("two digits ");
            builder.append(label).append(" is expected");
            byte pre = peek(error);
            if (pre == '-' || pre == ':') builder.append(" after '").append((char) pre).append("'");
            int length = end - ptr - error;
            if (length >= 10) length = 11;
            builder.append(": ").append(new ByteList(bytes, ptr - error, length, true));
            throw argumentError(context, builder.toString());
        }
        return total;*/
    }

    private IRubyObject parseInt(ThreadContext context, boolean parseSign) {
        int sign = 1;
        if (parseSign) {
            eatSpace();
            byte signByte = peek();
            if (signByte == '+') {
                ndigits++;
                advance();
            } else if (signByte == '-') {
                ndigits++;
                advance();
                sign = -1;
            }
        }

        long total = 0;
        while (!isEOS() && isDigit(0)) {
            total = total * 10 + (peek() - '0');
            advance();
            ndigits++;
        }

        return new RubyFixnum(context.runtime, sign * total);
    }
}
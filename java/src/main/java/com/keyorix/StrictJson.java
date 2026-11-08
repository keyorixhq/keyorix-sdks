package com.keyorix;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Strict RFC 8259 reader for server responses. Zero external dependencies.
 *
 * <p>Produces {@code Map<String,Object>} (objects), {@code List<Object>} (arrays),
 * {@code String}, {@code Boolean}, {@link Num} (numbers, kept as their source text)
 * and {@link #NULL}. Anything that is not exactly one well-formed JSON value
 * (truncated input, trailing data, bad escapes, raw control characters in a
 * string, unpaired surrogates, excessive nesting) is rejected with a {@link KeyorixException}; a
 * partial result is never returned. If an object repeats a key, the last
 * occurrence wins.
 */
final class StrictJson {

    /** JSON null. */
    static final Object NULL = new Object() {
        @Override public String toString() { return "null"; }
    };

    /** A JSON number, kept as its source text so callers choose the target type. */
    static final class Num {
        final String text;
        Num(String text) { this.text = text; }

        /** The value as a long, or throws {@link NumberFormatException} unless it is an integer that fits. */
        long asLong() {
            if (text.indexOf('.') >= 0 || text.indexOf('e') >= 0 || text.indexOf('E') >= 0) {
                throw new NumberFormatException("not an integer");
            }
            return Long.parseLong(text);
        }

        @Override public String toString() { return text; }
    }

    private static final int MAX_DEPTH = 128;

    private final String s;
    private int pos;

    private StrictJson(String s) {
        this.s = s;
    }

    /** Parses exactly one JSON value; leading and trailing whitespace is allowed. */
    static Object parse(String json) throws KeyorixException {
        if (json == null) throw fail(0);
        StrictJson p = new StrictJson(json);
        p.skipWs();
        Object v = p.value(0);
        p.skipWs();
        if (p.pos != json.length()) throw fail(p.pos);
        return v;
    }

    private static KeyorixException fail(int at) {
        return new KeyorixException("Malformed JSON in server response (offset " + at + ")");
    }

    private void skipWs() {
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
            else break;
        }
    }

    private Object value(int depth) throws KeyorixException {
        if (pos >= s.length()) throw fail(pos);
        char c = s.charAt(pos);
        switch (c) {
            case '{': return object(depth + 1);
            case '[': return array(depth + 1);
            case '"': return string();
            case 't': literal("true"); return Boolean.TRUE;
            case 'f': literal("false"); return Boolean.FALSE;
            case 'n': literal("null"); return NULL;
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return number();
                throw fail(pos);
        }
    }

    private void literal(String word) throws KeyorixException {
        if (!s.startsWith(word, pos)) throw fail(pos);
        pos += word.length();
    }

    private Map<String, Object> object(int depth) throws KeyorixException {
        if (depth > MAX_DEPTH) throw fail(pos);
        pos++; // {
        Map<String, Object> m = new LinkedHashMap<>();
        skipWs();
        if (pos < s.length() && s.charAt(pos) == '}') {
            pos++;
            return m;
        }
        while (true) {
            skipWs();
            if (pos >= s.length() || s.charAt(pos) != '"') throw fail(pos);
            String key = string();
            skipWs();
            if (pos >= s.length() || s.charAt(pos) != ':') throw fail(pos);
            pos++;
            skipWs();
            m.put(key, value(depth)); // a repeated key replaces the earlier one: last wins
            skipWs();
            if (pos >= s.length()) throw fail(pos);
            char c = s.charAt(pos++);
            if (c == '}') return m;
            if (c != ',') throw fail(pos - 1);
        }
    }

    private List<Object> array(int depth) throws KeyorixException {
        if (depth > MAX_DEPTH) throw fail(pos);
        pos++; // [
        List<Object> l = new ArrayList<>();
        skipWs();
        if (pos < s.length() && s.charAt(pos) == ']') {
            pos++;
            return l;
        }
        while (true) {
            skipWs();
            l.add(value(depth));
            skipWs();
            if (pos >= s.length()) throw fail(pos);
            char c = s.charAt(pos++);
            if (c == ']') return l;
            if (c != ',') throw fail(pos - 1);
        }
    }

    private String string() throws KeyorixException {
        pos++; // opening quote
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= s.length()) throw fail(pos); // unterminated
            char c = s.charAt(pos++);
            if (c == '"') return sb.toString();
            if (c < 0x20) throw fail(pos - 1); // raw control character
            if (c != '\\') {
                if (Character.isHighSurrogate(c)) {
                    if (pos >= s.length() || !Character.isLowSurrogate(s.charAt(pos))) throw fail(pos - 1);
                    sb.append(c).append(s.charAt(pos++));
                    continue;
                }
                if (Character.isLowSurrogate(c)) throw fail(pos - 1);
                sb.append(c);
                continue;
            }
            if (pos >= s.length()) throw fail(pos);
            char e = s.charAt(pos++);
            switch (e) {
                case '"': sb.append('"'); break;
                case '\\': sb.append('\\'); break;
                case '/': sb.append('/'); break;
                case 'b': sb.append('\b'); break;
                case 'f': sb.append('\f'); break;
                case 'n': sb.append('\n'); break;
                case 'r': sb.append('\r'); break;
                case 't': sb.append('\t'); break;
                case 'u': {
                    int cp = hex4(pos);
                    pos += 4;
                    if (Character.isHighSurrogate((char) cp)) {
                        // must be followed by an escaped low surrogate
                        if (pos + 6 > s.length() || s.charAt(pos) != '\\' || s.charAt(pos + 1) != 'u') throw fail(pos);
                        int lo = hex4(pos + 2);
                        if (!Character.isLowSurrogate((char) lo)) throw fail(pos + 2);
                        sb.append((char) cp).append((char) lo);
                        pos += 6;
                    } else if (Character.isLowSurrogate((char) cp)) {
                        throw fail(pos - 4);
                    } else {
                        sb.append((char) cp);
                    }
                    break;
                }
                default:
                    throw fail(pos - 1);
            }
        }
    }

    /** Reads four hex digits at {@code at} (ASCII only). */
    private int hex4(int at) throws KeyorixException {
        if (at + 4 > s.length()) throw fail(at);
        int v = 0;
        for (int k = 0; k < 4; k++) {
            char ch = s.charAt(at + k);
            int d = ch > 'f' ? -1 : Character.digit(ch, 16);
            if (d < 0) throw fail(at + k);
            v = v * 16 + d;
        }
        return v;
    }

    private Num number() throws KeyorixException {
        int start = pos;
        if (s.charAt(pos) == '-') pos++;
        if (pos >= s.length()) throw fail(pos);
        if (s.charAt(pos) == '0') {
            pos++;
        } else if (s.charAt(pos) >= '1' && s.charAt(pos) <= '9') {
            while (pos < s.length() && isDigit(s.charAt(pos))) pos++;
        } else {
            throw fail(pos);
        }
        if (pos < s.length() && s.charAt(pos) == '.') {
            pos++;
            int d = pos;
            while (pos < s.length() && isDigit(s.charAt(pos))) pos++;
            if (pos == d) throw fail(pos);
        }
        if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
            pos++;
            if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) pos++;
            int d = pos;
            while (pos < s.length() && isDigit(s.charAt(pos))) pos++;
            if (pos == d) throw fail(pos);
        }
        return new Num(s.substring(start, pos));
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }
}

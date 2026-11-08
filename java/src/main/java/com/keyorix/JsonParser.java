package com.keyorix;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Reads Keyorix API responses. Zero external dependencies.
 *
 * <p>A response body is parsed in full with {@link StrictJson}; malformed or
 * truncated input raises {@link KeyorixException} instead of yielding a
 * partial result. Fields are read from the response's {@code data} object, never
 * from deeper levels, and when a key is repeated the last occurrence wins.
 */
class JsonParser {

    private JsonParser() {}

    /** Extract token from login response: {"data":{"token":"..."}}; null if the response carries none (for example an MFA challenge). */
    static String parseToken(String json) throws KeyorixException {
        return extractString(json, "token");
    }

    /** Extract secret value from secret response: {"data":{"value":"..."}}; a missing or non-string value is an error.
     * An empty string value is valid and is returned as {@code ""}. */
    static String parseSecretValue(String json) throws KeyorixException {
        return requiredString(scope(json), "value");
    }

    /** Parse secret list from: {"data":{"secrets":[...]}} */
    static List<Secret> parseSecretList(String json) throws KeyorixException {
        List<Secret> result = new ArrayList<>();
        for (Map<String, Object> obj : arrayObjects(json, "secrets")) {
            result.add(parseSecret(obj));
        }
        return result;
    }

    /** Parse the secret node from an update response: {"data":{"id":...,"name":...}};  */
    static Secret parseSecretResponse(String json) throws KeyorixException {
        return parseSecret(scope(json));
    }

    /** Parse the recycle bin from: {"data":{"deleted":[...]}}; purge_at becomes {@link Secret#getPurgeAt()}. */
    static List<Secret> parseDeletedSecretList(String json, long projectId) throws KeyorixException {
        List<Secret> result = new ArrayList<>();
        for (Map<String, Object> obj : arrayObjects(json, "deleted")) {
            String type = string(obj, "type");
            String purgeAt = string(obj, "purge_at");
            result.add(new Secret(requiredLong(obj, "id"), requiredString(obj, "name"), type != null ? type : "", "",
                                  projectId, "", purgeAt != null ? purgeAt : ""));
        }
        return result;
    }

    /** Extract total_pages from a paginated list response: {"data":{...,"total_pages":N}} */
    static int parseTotalPages(String json) throws KeyorixException {
        long n = optionalLong(scope(json), "total_pages");
        if (n < Integer.MIN_VALUE || n > Integer.MAX_VALUE) {
            throw new KeyorixException("Unexpected JSON in server response: \"total_pages\" is out of range");
        }
        return (int) n;
    }

    /** Parse one created secret node from: {"data":{"id":..,"name":..,"type":..,"project_id":..}} */
    static Secret parseCreatedSecret(String json) throws KeyorixException {
        return parseSecret(scope(json));
    }

    /** Parse one created project from: {"data":{"id":..,"name":..,"description":..}} */
    static Project parseCreatedProject(String json) throws KeyorixException {
        return parseProject(scope(json));
    }

    /** Quotes s as a JSON string literal, escaping quotes, backslashes and control characters. */
    static String quote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    /** Parse project list from: {"data":{"projects":[...]}} */
    static List<Project> parseProjectList(String json) throws KeyorixException {
        List<Project> result = new ArrayList<>();
        for (Map<String, Object> obj : arrayObjects(json, "projects")) {
            result.add(parseProject(obj));
        }
        return result;
    }

    /** Parse environment list from: {"data":{"environments":[...]}} */
    static List<Environment> parseEnvironmentList(String json) throws KeyorixException {
        List<Environment> result = new ArrayList<>();
        for (Map<String, Object> obj : arrayObjects(json, "environments")) {
            result.add(parseEnvironment(obj));
        }
        return result;
    }

    /**
     * The string value of {@code key} in the response's data object, or null when
     * it is absent or null. A value of any other type, or malformed JSON, raises
     * {@link KeyorixException}.
     */
    static String extractString(String json, String key) throws KeyorixException {
        return string(scope(json), key);
    }

    /** True only when the key is present in the data object with the literal value true. */
    static boolean extractBoolean(String json, String key) throws KeyorixException {
        return Boolean.TRUE.equals(scope(json).get(key));
    }

    /**
     * The server's error code: the string {@code error} member of the top-level
     * object, or null if the body is not a JSON object carrying one. Never throws,
     * so it is safe on the body of an error response of any shape.
     */
    static String errorCode(String body) {
        if (body == null) return null;
        try {
            Object root = StrictJson.parse(body);
            if (root instanceof Map) {
                Object e = ((Map<?, ?>) root).get("error");
                return e instanceof String ? (String) e : null;
            }
        } catch (KeyorixException e) {
            // not JSON: no code
        }
        return null;
    }

    // ── helpers ─────────────────────────────────────────────────────────────────

    /** Parses a response body into its top-level object. */
    private static Map<String, Object> root(String json) throws KeyorixException {
        Object v = StrictJson.parse(json);
        if (!(v instanceof Map)) throw new KeyorixException("Unexpected JSON in server response: not an object");
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) v;
        return m;
    }

    /**
     * The response's {@code data} object, where every field the SDK reads lives.
     * A body that reports {@code "success"} as anything but true, or that has no
     * {@code data} object, is an error. This is a plain {@link KeyorixException}, also for
     * a 200 login response; it is deliberately not an {@link AuthException}.
     */
    private static Map<String, Object> scope(String json) throws KeyorixException {
        Map<String, Object> root = root(json);
        if (root.containsKey("success") && !Boolean.TRUE.equals(root.get("success"))) {
            throw new KeyorixException("Server response does not report success");
        }
        Object data = root.get("data");
        if (!(data instanceof Map)) throw new KeyorixException("Unexpected JSON in server response: no \"data\" object");
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) data;
        return m;
    }

    /**
     * The objects in the array under {@code key} of the data object. A missing or null
     * collection is deliberately an empty list (a server may encode an empty collection as
     * null); any other non-array value, or a non-object item, is an error.
     */
    private static List<Map<String, Object>> arrayObjects(String json, String key) throws KeyorixException {
        Object arr = scope(json).get(key);
        List<Map<String, Object>> out = new ArrayList<>();
        if (arr == null || arr == StrictJson.NULL) return out;
        if (!(arr instanceof List)) throw new KeyorixException("Unexpected JSON in server response: \"" + key + "\" is not an array");
        for (Object o : (List<?>) arr) {
            if (!(o instanceof Map)) throw new KeyorixException("Unexpected JSON in server response: \"" + key + "\" has a non-object item");
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) o;
            out.add(m);
        }
        return out;
    }

    /** The string under {@code key}; null when absent or null. Any other type is an error. */
    private static String string(Map<String, Object> o, String key) throws KeyorixException {
        Object v = o.get(key);
        if (v == null || v == StrictJson.NULL) return null;
        if (v instanceof String) return (String) v;
        throw new KeyorixException("Unexpected JSON in server response: \"" + key + "\" is not a string");
    }

    /** The string under {@code key}, which must be present. */
    private static String requiredString(Map<String, Object> o, String key) throws KeyorixException {
        String v = string(o, key);
        if (v == null) throw new KeyorixException("Unexpected JSON in server response: \"" + key + "\" is missing");
        return v;
    }

    /** The integer under {@code key}; 0 when absent or null (an absent optional field such as project_id is deliberately 0). Anything else that is not a 64-bit integer is an error. */
    private static long optionalLong(Map<String, Object> o, String key) throws KeyorixException {
        Object v = o.get(key);
        if (v == null || v == StrictJson.NULL) return 0;
        return asLong(v, key);
    }

    /** The integer under {@code key}, which must be present and a 64-bit integer. */
    private static long requiredLong(Map<String, Object> o, String key) throws KeyorixException {
        Object v = o.get(key);
        if (v == null || v == StrictJson.NULL) {
            throw new KeyorixException("Unexpected JSON in server response: \"" + key + "\" is missing");
        }
        return asLong(v, key);
    }

    private static long asLong(Object v, String key) throws KeyorixException {
        if (v instanceof StrictJson.Num) {
            try {
                return ((StrictJson.Num) v).asLong();
            } catch (NumberFormatException e) {
                // fall through
            }
        }
        throw new KeyorixException("Unexpected JSON in server response: \"" + key + "\" is not a 64-bit integer");
    }

    private static Secret parseSecret(Map<String, Object> obj) throws KeyorixException {
        long id = requiredLong(obj, "id");
        String name = requiredString(obj, "name");
        String type = string(obj, "type");
        String env = string(obj, "environment_name");
        long projectId = optionalLong(obj, "project_id");
        String createdAt = string(obj, "created_at");
        return new Secret(id, name, type != null ? type : "", env != null ? env : "",
                          projectId, createdAt != null ? createdAt : "");
    }

    private static Project parseProject(Map<String, Object> obj) throws KeyorixException {
        long id = requiredLong(obj, "id");
        String name = requiredString(obj, "name");
        String description = string(obj, "description");
        String createdAt = string(obj, "created_at");
        return new Project(id, name, description != null ? description : "",
                            createdAt != null ? createdAt : "");
    }

    private static Environment parseEnvironment(Map<String, Object> obj) throws KeyorixException {
        long id = requiredLong(obj, "id");
        String name = requiredString(obj, "name");
        long projectId = optionalLong(obj, "project_id");
        return new Environment(id, projectId, name);
    }
}

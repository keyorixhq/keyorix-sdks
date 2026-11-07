package com.keyorix;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Reads Keyorix API responses. Zero external dependencies.
 *
 * <p>A response body is parsed in full with {@link StrictJson}; malformed or
 * truncated input raises {@link KeyorixException} instead of yielding a
 * partial result. Fields are read from the response's {@code data} object (or
 * from the top-level object when the body has no {@code data} object), never
 * from deeper levels, and when a key is repeated the last occurrence wins.
 */
class JsonParser {

    private JsonParser() {}

    /** Extract token from login response: {"data":{"token":"..."}} */
    static String parseToken(String json) throws KeyorixException {
        return extractString(json, "token");
    }

    /** Extract secret value from secret response: {"data":{"value":"..."}} */
    static String parseSecretValue(String json) throws KeyorixException {
        return extractString(json, "value");
    }

    /** Parse secret list from: {"data":{"secrets":[...]}} */
    static List<Secret> parseSecretList(String json) throws KeyorixException {
        List<Secret> result = new ArrayList<>();
        for (Map<String, Object> obj : arrayObjects(json, "secrets")) {
            Secret s = parseSecret(obj);
            if (s != null) result.add(s);
        }
        return result;
    }

    /** Parse the secret node from an update response: {"data":{"id":...,"name":...}}; null if it has no name. */
    static Secret parseSecretResponse(String json) throws KeyorixException {
        return parseSecret(scope(json));
    }

    /** Parse the recycle bin from: {"data":{"deleted":[...]}}; purge_at becomes {@link Secret#getPurgeAt()}. */
    static List<Secret> parseDeletedSecretList(String json, long projectId) throws KeyorixException {
        List<Secret> result = new ArrayList<>();
        for (Map<String, Object> obj : arrayObjects(json, "deleted")) {
            try {
                String name = string(obj, "name");
                if (name == null) continue;
                String type = string(obj, "type");
                String purgeAt = string(obj, "purge_at");
                result.add(new Secret(longField(obj, "id"), name, type != null ? type : "", "", projectId, "",
                                      purgeAt != null ? purgeAt : ""));
            } catch (NumberFormatException e) {
                // skip an unparseable entry, as parseSecretList does
            }
        }
        return result;
    }

    /** Extract total_pages from a paginated list response: {"data":{...,"total_pages":N}} */
    static int parseTotalPages(String json) throws KeyorixException {
        try {
            return (int) longField(scope(json), "total_pages");
        } catch (NumberFormatException e) {
            return 0;
        }
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
            Project p = parseProject(obj);
            if (p != null) result.add(p);
        }
        return result;
    }

    /** Parse environment list from: {"data":{"environments":[...]}} */
    static List<Environment> parseEnvironmentList(String json) throws KeyorixException {
        List<Environment> result = new ArrayList<>();
        for (Map<String, Object> obj : arrayObjects(json, "environments")) {
            Environment e = parseEnvironment(obj);
            if (e != null) result.add(e);
        }
        return result;
    }

    /**
     * The string value of {@code key} in the response's data object, or null when
     * it is absent or not a string. Malformed JSON raises {@link KeyorixException}.
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

    /** The object the response's fields live in: its {@code data} object, else the top-level object. */
    private static Map<String, Object> scope(String json) throws KeyorixException {
        Map<String, Object> root = root(json);
        Object data = root.get("data");
        if (data instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) data;
            return m;
        }
        return root;
    }

    /** The objects in the array under {@code key} of the data object; missing or null means none. */
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

    private static String string(Map<String, Object> o, String key) {
        Object v = o.get(key);
        return v instanceof String ? (String) v : null;
    }

    /** The integer under {@code key}; 0 when absent or not a number; NumberFormatException when it is not a long. */
    private static long longField(Map<String, Object> o, String key) {
        Object v = o.get(key);
        return v instanceof StrictJson.Num ? ((StrictJson.Num) v).asLong() : 0;
    }

    private static Secret parseSecret(Map<String, Object> obj) {
        try {
            long id = longField(obj, "id");
            String name = string(obj, "name");
            String type = string(obj, "type");
            String env = string(obj, "environment_name");
            long projectId = longField(obj, "project_id");
            String createdAt = string(obj, "created_at");
            if (name == null) return null;
            return new Secret(id, name, type != null ? type : "", env != null ? env : "",
                              projectId, createdAt != null ? createdAt : "");
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Project parseProject(Map<String, Object> obj) {
        try {
            long id = longField(obj, "id");
            String name = string(obj, "name");
            String description = string(obj, "description");
            String createdAt = string(obj, "created_at");
            if (name == null) return null;
            return new Project(id, name, description != null ? description : "",
                                createdAt != null ? createdAt : "");
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Environment parseEnvironment(Map<String, Object> obj) {
        try {
            long id = longField(obj, "id");
            String name = string(obj, "name");
            long projectId = longField(obj, "project_id");
            if (name == null) return null;
            return new Environment(id, projectId, name);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}

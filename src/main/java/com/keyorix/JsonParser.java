package com.keyorix;

import java.util.ArrayList;
import java.util.List;

/**
 * Minimal JSON parser for Keyorix API responses.
 * Zero external dependencies — hand-rolled for the specific response shapes.
 */
class JsonParser {

    /** Extract token from login response: {"data":{"token":"..."}} */
    static String parseToken(String json) {
        return extractString(json, "token");
    }

    /** Extract secret value from secret response: {"data":{"value":"..."}} */
    static String parseSecretValue(String json) {
        return extractString(json, "value");
    }

    /** Parse secret list from: {"data":{"secrets":[...]}} */
    static List<Secret> parseSecretList(String json) {
        List<Secret> result = new ArrayList<>();
        int secretsIdx = json.indexOf("\"secrets\"");
        if (secretsIdx == -1) return result;

        int arrStart = json.indexOf('[', secretsIdx);
        int arrEnd = findMatchingBracket(json, arrStart, '[', ']');
        if (arrStart == -1 || arrEnd == -1) return result;

        String arr = json.substring(arrStart + 1, arrEnd);
        List<String> objects = splitObjects(arr);
        for (String obj : objects) {
            Secret s = parseSecret(obj);
            if (s != null) result.add(s);
        }
        return result;
    }

    private static Secret parseSecret(String obj) {
        try {
            long id = parseLong(obj, "ID");
            String name = extractString(obj, "Name");
            String type = extractString(obj, "Type");
            String env = extractString(obj, "environment_name");
            long projectId = parseLong(obj, "ProjectID");
            String createdAt = extractString(obj, "CreatedAt");
            if (name == null) return null;
            return new Secret(id, name, type != null ? type : "", env != null ? env : "",
                              projectId, createdAt != null ? createdAt : "");
        } catch (Exception e) {
            return null;
        }
    }

    static String extractString(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx == -1) return null;
        int colon = json.indexOf(':', idx + search.length());
        if (colon == -1) return null;
        int start = json.indexOf('"', colon + 1);
        if (start == -1) return null;
        int end = start + 1;
        while (end < json.length()) {
            if (json.charAt(end) == '"' && json.charAt(end - 1) != '\\') break;
            end++;
        }
        return json.substring(start + 1, end);
    }

    private static long parseLong(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx == -1) return 0;
        int colon = json.indexOf(':', idx + search.length());
        if (colon == -1) return 0;
        int start = colon + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) end++;
        if (start == end) return 0;
        return Long.parseLong(json.substring(start, end));
    }

    private static int findMatchingBracket(String json, int start, char open, char close) {
        if (start == -1 || start >= json.length()) return -1;
        int depth = 0;
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == open) depth++;
            else if (c == close) {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    private static List<String> splitObjects(String arr) {
        List<String> result = new ArrayList<>();
        int i = 0;
        while (i < arr.length()) {
            if (arr.charAt(i) == '{') {
                int end = findMatchingBracket(arr, i, '{', '}');
                if (end == -1) break;
                result.add(arr.substring(i, end + 1));
                i = end + 1;
            } else {
                i++;
            }
        }
        return result;
    }
}

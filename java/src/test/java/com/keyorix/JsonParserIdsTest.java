package com.keyorix;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Ids are 64-bit integers. An id that is not one must be reported, never
 * turned into 0 and never cause a list entry to be dropped.
 */
class JsonParserIdsTest {

    private static String secrets(String idJson) {
        return "{\"data\":{\"secrets\":[{\"id\":1,\"name\":\"first\",\"project_id\":1},"
            + "{\"id\":" + idJson + ",\"name\":\"second\",\"project_id\":1}],\"total_pages\":1}}";
    }

    @Test
    void largestLongIdIsKept() throws Exception {
        List<Secret> l = JsonParser.parseSecretList(secrets("9223372036854775807"));
        assertEquals(2, l.size());
        assertEquals(Long.MAX_VALUE, l.get(1).getId());
        assertEquals(Long.MIN_VALUE, JsonParser.parseSecretList(secrets("-9223372036854775808")).get(1).getId());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "9223372036854775808", "-9223372036854775809", "99999999999999999999999999",
        "\"abc\"", "\"5\"", "\"\"", "null", "true", "{}", "[]", "[5]", "1.5", "1.0", "1e2", "-0.5"
    })
    void anIdThatIsNotALongIsAnErrorNotAZeroOrADroppedEntry(String idJson) {
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretList(secrets(idJson)));
    }

    @Test
    void aMissingIdIsAnError() {
        String json = "{\"data\":{\"secrets\":[{\"name\":\"no-id\",\"project_id\":1}]}}";
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretList(json));
    }

    @Test
    void aListEntryWithoutAStringNameIsAnErrorNotSkipped() {
        assertThrows(KeyorixException.class,
            () -> JsonParser.parseSecretList("{\"data\":{\"secrets\":[{\"id\":1,\"project_id\":1}]}}"));
        assertThrows(KeyorixException.class,
            () -> JsonParser.parseSecretList("{\"data\":{\"secrets\":[{\"id\":1,\"name\":5,\"project_id\":1}]}}"));
        assertThrows(KeyorixException.class,
            () -> JsonParser.parseSecretList("{\"data\":{\"secrets\":[{\"id\":1,\"name\":null,\"project_id\":1}]}}"));
    }

    @Test
    void optionalFieldsMayBeAbsentOrNullButNotWrongTyped() throws Exception {
        Secret s = JsonParser.parseSecretList(
            "{\"data\":{\"secrets\":[{\"id\":1,\"name\":\"n\",\"type\":null}]}}").get(0);
        assertEquals("", s.getType());
        assertEquals(0L, s.getProjectId());
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretList(
            "{\"data\":{\"secrets\":[{\"id\":1,\"name\":\"n\",\"type\":7}]}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretList(
            "{\"data\":{\"secrets\":[{\"id\":1,\"name\":\"n\",\"project_id\":\"x\"}]}}"));
    }

    @Test
    void projectsAndEnvironmentsRejectBadIds() {
        assertThrows(KeyorixException.class, () -> JsonParser.parseProjectList(
            "{\"data\":{\"projects\":[{\"id\":\"abc\",\"name\":\"p\"}]}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseProjectList(
            "{\"data\":{\"projects\":[{\"id\":9223372036854775808,\"name\":\"p\"}]}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseEnvironmentList(
            "{\"data\":{\"environments\":[{\"id\":1,\"project_id\":\"abc\",\"name\":\"e\"}]}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseEnvironmentList(
            "{\"data\":{\"environments\":[{\"id\":99999999999999999999,\"project_id\":1,\"name\":\"e\"}]}}"));
    }

    @Test
    void deletedAndSingleResponsesRejectBadIds() {
        assertThrows(KeyorixException.class, () -> JsonParser.parseDeletedSecretList(
            "{\"data\":{\"deleted\":[{\"id\":\"x\",\"name\":\"d\"}]}}", 1));
        assertThrows(KeyorixException.class, () -> JsonParser.parseCreatedSecret(
            "{\"data\":{\"id\":\"x\",\"name\":\"d\"}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretResponse(
            "{\"data\":{\"id\":99999999999999999999,\"name\":\"d\"}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseCreatedProject(
            "{\"data\":{\"id\":\"x\",\"name\":\"d\"}}"));
    }

    @Test
    void totalPagesMustBeAnIntegerWhenPresent() throws Exception {
        assertEquals(0, JsonParser.parseTotalPages("{\"data\":{}}"));
        assertEquals(3, JsonParser.parseTotalPages("{\"data\":{\"total_pages\":3}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseTotalPages("{\"data\":{\"total_pages\":\"3\"}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseTotalPages("{\"data\":{\"total_pages\":2.5}}"));
        // would wrap to a small or negative int if narrowed from long
        assertThrows(KeyorixException.class, () -> JsonParser.parseTotalPages("{\"data\":{\"total_pages\":4294967297}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseTotalPages("{\"data\":{\"total_pages\":99999999999999999999}}"));
    }
}

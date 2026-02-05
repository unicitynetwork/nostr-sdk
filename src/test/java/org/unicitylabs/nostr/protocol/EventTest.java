package org.unicitylabs.nostr.protocol;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Unit tests for Event class — the fundamental Nostr data structure.
 */
public class EventTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    // --- Construction & Defaults ---

    @Test
    public void testDefaultConstructorInitializesEmptyState() {
        Event event = new Event();
        assertNull(event.getId());
        assertNull(event.getPubkey());
        assertEquals(0, event.getCreatedAt());
        assertEquals(0, event.getKind());
        assertNotNull(event.getTags());
        assertTrue(event.getTags().isEmpty());
        assertEquals("", event.getContent());
        assertNull(event.getSig());
    }

    @Test
    public void testFullConstructorCopiesAllFields() {
        List<List<String>> tags = new ArrayList<>();
        tags.add(Arrays.asList("p", "pk1"));

        Event event = new Event("id1", "pubkey1", 1700000000L, 1, tags, "hello", "sig1");

        assertEquals("id1", event.getId());
        assertEquals("pubkey1", event.getPubkey());
        assertEquals(1700000000L, event.getCreatedAt());
        assertEquals(1, event.getKind());
        assertEquals(1, event.getTags().size());
        assertEquals("hello", event.getContent());
        assertEquals("sig1", event.getSig());
    }

    @Test
    public void testFullConstructorMakesDefensiveCopyOfTags() {
        List<List<String>> originalTags = new ArrayList<>();
        originalTags.add(Arrays.asList("p", "pk1"));

        Event event = new Event("id1", "pubkey1", 0, 1, originalTags, "", null);

        // Modify original list
        originalTags.add(Arrays.asList("e", "ev1"));

        // Event's tags should not be affected
        assertEquals(1, event.getTags().size());
    }

    @Test
    public void testFullConstructorWithNullTagsDefaultsToEmptyList() {
        Event event = new Event("id1", "pk1", 0, 1, null, "content", null);
        assertNotNull(event.getTags());
        assertTrue(event.getTags().isEmpty());
    }

    @Test
    public void testFullConstructorWithNullContentDefaultsToEmptyString() {
        Event event = new Event("id1", "pk1", 0, 1, null, null, null);
        assertEquals("", event.getContent());
    }

    // --- Setters with null safety ---

    @Test
    public void testSetTagsWithNullDefaultsToEmptyList() {
        Event event = new Event();
        event.setTags(null);
        assertNotNull(event.getTags());
        assertTrue(event.getTags().isEmpty());
    }

    @Test
    public void testSetTagsMakesDefensiveCopy() {
        Event event = new Event();
        List<List<String>> tags = new ArrayList<>();
        tags.add(Arrays.asList("p", "pk1"));
        event.setTags(tags);

        tags.add(Arrays.asList("e", "ev1"));
        assertEquals(1, event.getTags().size());
    }

    @Test
    public void testSetContentWithNullDefaultsToEmptyString() {
        Event event = new Event();
        event.setContent(null);
        assertEquals("", event.getContent());
    }

    // --- Tag Access Methods ---

    @Test
    public void testGetTagValueReturnsFirstMatch() {
        Event event = new Event();
        event.setTags(Arrays.asList(
                Arrays.asList("p", "pubkey1"),
                Arrays.asList("e", "event1"),
                Arrays.asList("p", "pubkey2")
        ));
        assertEquals("pubkey1", event.getTagValue("p"));
    }

    @Test
    public void testGetTagValueReturnsNullForMissingTag() {
        Event event = new Event();
        event.setTags(Arrays.asList(Arrays.asList("p", "pubkey1")));
        assertNull(event.getTagValue("e"));
    }

    @Test
    public void testGetTagValueWithEmptyTagsList() {
        Event event = new Event();
        assertNull(event.getTagValue("p"));
    }

    @Test
    public void testGetTagValueSkipsTagsWithOnlyNameAndNoValue() {
        Event event = new Event();
        event.setTags(Arrays.asList(
                Arrays.asList("p"),  // Only name, no value
                Arrays.asList("p", "pubkey1")
        ));
        assertEquals("pubkey1", event.getTagValue("p"));
    }

    @Test
    public void testGetTagValueWithOnlySingleElementTag() {
        Event event = new Event();
        event.setTags(Arrays.asList(Collections.singletonList("p")));
        assertNull(event.getTagValue("p"));
    }

    @Test
    public void testGetTagValuesReturnsAllMatches() {
        Event event = new Event();
        event.setTags(Arrays.asList(
                Arrays.asList("p", "pk1"),
                Arrays.asList("e", "ev1"),
                Arrays.asList("p", "pk2"),
                Arrays.asList("p", "pk3")
        ));
        List<String> values = event.getTagValues("p");
        assertEquals(Arrays.asList("pk1", "pk2", "pk3"), values);
    }

    @Test
    public void testGetTagValuesReturnsEmptyForNoMatches() {
        Event event = new Event();
        event.setTags(Arrays.asList(Arrays.asList("e", "ev1")));
        List<String> values = event.getTagValues("p");
        assertTrue(values.isEmpty());
    }

    @Test
    public void testGetTagValuesWithEmptyTagsList() {
        Event event = new Event();
        assertTrue(event.getTagValues("p").isEmpty());
    }

    @Test
    public void testHasTagReturnsTrue() {
        Event event = new Event();
        event.setTags(Arrays.asList(Arrays.asList("p", "pk1")));
        assertTrue(event.hasTag("p"));
    }

    @Test
    public void testHasTagReturnsTrueEvenForSingleElementTag() {
        Event event = new Event();
        event.setTags(Arrays.asList(Collections.singletonList("p")));
        assertTrue(event.hasTag("p"));
    }

    @Test
    public void testHasTagReturnsFalseForMissing() {
        Event event = new Event();
        event.setTags(Arrays.asList(Arrays.asList("p", "pk1")));
        assertFalse(event.hasTag("e"));
    }

    @Test
    public void testHasTagReturnsFalseOnEmptyTags() {
        Event event = new Event();
        assertFalse(event.hasTag("p"));
    }

    // --- Equality & Hashing ---

    @Test
    public void testEqualsByIdSameId() {
        Event a = new Event("abc", "pk1", 0, 1, null, "a", null);
        Event b = new Event("abc", "pk2", 0, 2, null, "b", null);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    public void testNotEqualsDifferentId() {
        Event a = new Event("abc", "pk1", 0, 1, null, "", null);
        Event b = new Event("xyz", "pk1", 0, 1, null, "", null);
        assertNotEquals(a, b);
    }

    @Test
    public void testNotEqualsNull() {
        Event a = new Event("abc", "pk1", 0, 1, null, "", null);
        assertNotEquals(a, null);
    }

    @Test
    public void testNotEqualsDifferentType() {
        Event a = new Event("abc", "pk1", 0, 1, null, "", null);
        assertNotEquals(a, "abc");
    }

    @Test
    public void testEqualsSelf() {
        Event a = new Event("abc", "pk1", 0, 1, null, "", null);
        assertEquals(a, a);
    }

    @Test
    public void testBothNullIdsAreEqual() {
        Event a = new Event(null, "pk1", 0, 1, null, "", null);
        Event b = new Event(null, "pk2", 0, 2, null, "", null);
        assertEquals(a, b);
    }

    @Test
    public void testEmptyStringIdNotEqualToNullId() {
        Event a = new Event("", "pk1", 0, 1, null, "", null);
        Event b = new Event(null, "pk1", 0, 1, null, "", null);
        assertNotEquals(a, b);
    }

    // --- JSON Serialization ---

    @Test
    public void testJsonRoundTrip() throws Exception {
        Event original = new Event("id123", "pubkey456", 1700000000L, 1,
                Arrays.asList(Arrays.asList("p", "pk1"), Arrays.asList("e", "ev1", "", "reply")),
                "Hello world", "sig789");

        String json = objectMapper.writeValueAsString(original);
        Event restored = objectMapper.readValue(json, Event.class);

        assertEquals(original.getId(), restored.getId());
        assertEquals(original.getPubkey(), restored.getPubkey());
        assertEquals(original.getCreatedAt(), restored.getCreatedAt());
        assertEquals(original.getKind(), restored.getKind());
        assertEquals(original.getTags(), restored.getTags());
        assertEquals(original.getContent(), restored.getContent());
        assertEquals(original.getSig(), restored.getSig());
    }

    @Test
    public void testJsonFieldNamesUseSnakeCase() throws Exception {
        Event event = new Event();
        event.setCreatedAt(1700000000L);
        String json = objectMapper.writeValueAsString(event);
        assertTrue(json.contains("\"created_at\""));
        assertFalse(json.contains("\"createdAt\""));
    }

    @Test
    public void testTagsSerializeAsArrayOfArrays() throws Exception {
        Event event = new Event();
        event.setTags(Arrays.asList(
                Arrays.asList("p", "pk1"),
                Arrays.asList("e", "ev1", "", "reply")
        ));
        String json = objectMapper.writeValueAsString(event);
        assertTrue(json.contains("[[\"p\",\"pk1\"],[\"e\",\"ev1\",\"\",\"reply\"]]"));
    }

    @Test
    public void testDeserializeMinimalJson() throws Exception {
        String json = "{\"id\":\"abc\",\"pubkey\":\"def\",\"created_at\":100,\"kind\":1,\"tags\":[],\"content\":\"hi\",\"sig\":\"xyz\"}";
        Event event = objectMapper.readValue(json, Event.class);
        assertEquals("abc", event.getId());
        assertEquals("def", event.getPubkey());
        assertEquals(100L, event.getCreatedAt());
        assertEquals(1, event.getKind());
        assertTrue(event.getTags().isEmpty());
        assertEquals("hi", event.getContent());
        assertEquals("xyz", event.getSig());
    }

    // --- toString edge cases ---

    @Test
    public void testToStringWithNullFields() {
        Event event = new Event();
        // Should not throw NullPointerException
        String str = event.toString();
        assertNotNull(str);
        assertTrue(str.contains("null"));
    }

    @Test
    public void testToStringWithShortId() {
        Event event = new Event();
        event.setId("short");
        event.setPubkey("pk");
        String str = event.toString();
        assertNotNull(str);
    }
}

package org.unicitylabs.nostr.protocol;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * Tests for Event mutability and equality edge cases.
 * Documents known issues with tags mutability.
 *
 * Techniques: [EG] Error Guessing, [RB] Risk-Based Testing
 */
public class EventMutabilityTest {

    // ==========================================================
    // Tags Mutability (Known Issue)
    // ==========================================================

    @Test
    public void testTagsListIsDirectlyExposed() {
        Event event = new Event("id", "pubkey", 1000, 1,
                Arrays.asList(Arrays.asList("p", "pubkey1")),
                "content", "sig");

        // WARNING: getTags() returns the internal list directly
        // Callers CAN modify internal state
        List<List<String>> tags = event.getTags();
        int originalSize = tags.size();

        tags.add(Arrays.asList("e", "eventid"));

        // Tags list was mutated
        assertEquals(originalSize + 1, event.getTags().size());
    }

    @Test
    public void testModifyingTagsAffectsEvent() {
        List<List<String>> initialTags = new ArrayList<>();
        initialTags.add(new ArrayList<>(Arrays.asList("t", "topic")));

        Event event = new Event("id", "pubkey", 1000, 1,
                initialTags, "test", "sig");

        // Modify the tag value through getTags()
        event.getTags().get(0).set(1, "modified");

        // The event's tag value is now changed
        assertEquals("modified", event.getTagValue("t"));
    }

    @Test
    public void testClearingTagsArrayAffectsEvent() {
        Event event = new Event("id", "pubkey", 1000, 1,
                Arrays.asList(Arrays.asList("p", "pk1"), Arrays.asList("e", "e1")),
                "test", "sig");

        assertEquals(2, event.getTags().size());

        // Clear tags through getter
        event.getTags().clear();

        assertEquals(0, event.getTags().size());
    }

    // ==========================================================
    // Content Mutability
    // ==========================================================

    @Test
    public void testContentCanBeModified() {
        Event event = new Event("id", "pubkey", 1000, 1,
                new ArrayList<>(), "original", "sig");

        event.setContent("modified");

        assertEquals("modified", event.getContent());
    }

    // ==========================================================
    // Event Equality (Java Finding #4)
    // ==========================================================

    @Test
    public void testEventsWithSameIdAreEqual() {
        Event event1 = new Event("same-id", "pk1", 1000, 1, new ArrayList<>(), "c1", "sig1");
        Event event2 = new Event("same-id", "pk2", 2000, 2, new ArrayList<>(), "c2", "sig2");

        // Events are equal if they have the same ID
        assertEquals(event1, event2);
    }

    @Test
    public void testEventsWithDifferentIdsAreNotEqual() {
        Event event1 = new Event("id1", "pk", 1000, 1, new ArrayList<>(), "c", "sig");
        Event event2 = new Event("id2", "pk", 1000, 1, new ArrayList<>(), "c", "sig");

        assertNotEquals(event1, event2);
    }

    @Test
    public void testTwoNullIdEventsAreEqual() {
        // WARNING: This is the Java finding #4
        // Two events with id=null are considered equal
        Event event1 = new Event(null, "pk1", 1000, 1, new ArrayList<>(), "c1", "sig1");
        Event event2 = new Event(null, "pk2", 2000, 2, new ArrayList<>(), "c2", "sig2");

        // This is problematic - both are considered equal
        assertEquals("Two null-ID events are considered equal", event1, event2);
    }

    @Test
    public void testNullIdEventsInHashSetLoseData() {
        // WARNING: Demonstrates data loss with null-ID events in HashSet
        Event event1 = new Event(null, "pk1", 1000, 1, new ArrayList<>(), "content1", "sig1");
        Event event2 = new Event(null, "pk2", 2000, 2, new ArrayList<>(), "content2", "sig2");

        Set<Event> eventSet = new HashSet<>();
        eventSet.add(event1);
        eventSet.add(event2);

        // Only one event in set because they have equal hash and equal()
        assertEquals("Data loss: both null-ID events are treated as one", 1, eventSet.size());
    }

    @Test
    public void testEventNotEqualsNull() {
        Event event = new Event("id", "pk", 1000, 1, new ArrayList<>(), "c", "sig");
        assertNotEquals(event, null);
    }

    @Test
    public void testEventNotEqualsDifferentType() {
        Event event = new Event("id", "pk", 1000, 1, new ArrayList<>(), "c", "sig");
        assertNotEquals(event, "not an event");
    }

    @Test
    public void testEventEqualsSelf() {
        Event event = new Event("id", "pk", 1000, 1, new ArrayList<>(), "c", "sig");
        assertEquals(event, event);
    }

    // ==========================================================
    // Constructor Defensive Copy Tests
    // ==========================================================

    @Test
    public void testConstructorCopiesTags() {
        List<List<String>> originalTags = new ArrayList<>();
        originalTags.add(new ArrayList<>(Arrays.asList("p", "pk1")));

        Event event = new Event("id", "pk", 1000, 1, originalTags, "c", "sig");

        // Modify original list
        originalTags.add(new ArrayList<>(Arrays.asList("e", "e1")));

        // Event should not be affected (constructor made a copy)
        assertEquals(1, event.getTags().size());
    }

    @Test
    public void testSetTagsCopiesList() {
        Event event = new Event();

        List<List<String>> tags = new ArrayList<>();
        tags.add(new ArrayList<>(Arrays.asList("p", "pk1")));

        event.setTags(tags);

        // Modify original
        tags.add(new ArrayList<>(Arrays.asList("e", "e1")));

        // Event should not be affected (setTags made a copy)
        assertEquals(1, event.getTags().size());
    }

    @Test
    public void testSetTagsWithNullDefaultsToEmptyList() {
        Event event = new Event();
        event.setTags(null);

        assertNotNull(event.getTags());
        assertTrue(event.getTags().isEmpty());
    }

    @Test
    public void testSetContentWithNullDefaultsToEmptyString() {
        Event event = new Event();
        event.setContent(null);

        assertNotNull(event.getContent());
        assertEquals("", event.getContent());
    }

    // ==========================================================
    // Tag Helper Methods
    // ==========================================================

    @Test
    public void testGetTagValueReturnsFirstMatch() {
        Event event = new Event("id", "pk", 1000, 1,
                Arrays.asList(
                        Arrays.asList("p", "pk1", "relay1"),
                        Arrays.asList("p", "pk2", "relay2")
                ),
                "c", "sig");

        // Returns first match only
        assertEquals("pk1", event.getTagValue("p"));
    }

    @Test
    public void testGetTagValueReturnsNullForMissingTag() {
        Event event = new Event("id", "pk", 1000, 1, new ArrayList<>(), "c", "sig");

        assertNull(event.getTagValue("p"));
    }

    @Test
    public void testGetTagValueSkipsSingleElementTags() {
        Event event = new Event("id", "pk", 1000, 1,
                Arrays.asList(Arrays.asList("p")), // Tag with only name, no value
                "c", "sig");

        assertNull(event.getTagValue("p"));
    }

    @Test
    public void testGetTagValuesReturnsAllMatches() {
        Event event = new Event("id", "pk", 1000, 1,
                Arrays.asList(
                        Arrays.asList("p", "pk1"),
                        Arrays.asList("p", "pk2"),
                        Arrays.asList("e", "e1")
                ),
                "c", "sig");

        List<String> pValues = event.getTagValues("p");
        assertEquals(2, pValues.size());
        assertTrue(pValues.contains("pk1"));
        assertTrue(pValues.contains("pk2"));
    }

    @Test
    public void testGetTagValuesReturnsEmptyForNoMatches() {
        Event event = new Event("id", "pk", 1000, 1, new ArrayList<>(), "c", "sig");

        List<String> values = event.getTagValues("p");
        assertNotNull(values);
        assertTrue(values.isEmpty());
    }

    @Test
    public void testHasTagReturnsTrueWhenPresent() {
        Event event = new Event("id", "pk", 1000, 1,
                Arrays.asList(Arrays.asList("p", "pk1")),
                "c", "sig");

        assertTrue(event.hasTag("p"));
    }

    @Test
    public void testHasTagReturnsTrueForSingleElementTag() {
        Event event = new Event("id", "pk", 1000, 1,
                Arrays.asList(Arrays.asList("p")), // Tag with only name
                "c", "sig");

        assertTrue(event.hasTag("p"));
    }

    @Test
    public void testHasTagReturnsFalseWhenMissing() {
        Event event = new Event("id", "pk", 1000, 1,
                Arrays.asList(Arrays.asList("p", "pk1")),
                "c", "sig");

        assertFalse(event.hasTag("e"));
    }

    @Test
    public void testHasTagReturnsFalseOnEmptyTags() {
        Event event = new Event("id", "pk", 1000, 1, new ArrayList<>(), "c", "sig");

        assertFalse(event.hasTag("p"));
    }

    // ==========================================================
    // toString Tests
    // ==========================================================

    @Test
    public void testToStringDoesNotLeakFullId() {
        Event event = new Event(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "pubkey123456789012345678901234567890123456789012345678901234567890",
                1000, 1, new ArrayList<>(), "content", "sig");

        String str = event.toString();

        // Should not contain full 64-char ID
        assertFalse(str.contains("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
        assertTrue(str.contains("..."));
    }

    @Test
    public void testToStringHandlesNullId() {
        Event event = new Event(null, null, 1000, 1, new ArrayList<>(), "content", "sig");

        // Should not throw NPE
        String str = event.toString();
        assertNotNull(str);
        assertTrue(str.contains("null"));
    }

    // ==========================================================
    // HashCode Tests
    // ==========================================================

    @Test
    public void testHashCodeBasedOnId() {
        Event event1 = new Event("same-id", "pk1", 1000, 1, new ArrayList<>(), "c1", "sig1");
        Event event2 = new Event("same-id", "pk2", 2000, 2, new ArrayList<>(), "c2", "sig2");

        assertEquals(event1.hashCode(), event2.hashCode());
    }

    @Test
    public void testHashCodeDifferentIds() {
        Event event1 = new Event("id1", "pk", 1000, 1, new ArrayList<>(), "c", "sig");
        Event event2 = new Event("id2", "pk", 1000, 1, new ArrayList<>(), "c", "sig");

        // Hash codes are likely different (not guaranteed but very probable)
        assertNotEquals(event1.hashCode(), event2.hashCode());
    }
}

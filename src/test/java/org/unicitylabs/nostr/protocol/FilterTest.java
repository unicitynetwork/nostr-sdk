package org.unicitylabs.nostr.protocol;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Unit tests for Filter class.
 */
public class FilterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void testEmptyFilter() {
        Filter filter = new Filter();
        assertNull(filter.getIds());
        assertNull(filter.getAuthors());
        assertNull(filter.getKinds());
    }

    @Test
    public void testBuilderWithIds() {
        Filter filter = Filter.builder()
                .ids("id1", "id2")
                .build();

        assertEquals(Arrays.asList("id1", "id2"), filter.getIds());
    }

    @Test
    public void testBuilderWithIdsList() {
        Filter filter = Filter.builder()
                .ids(Arrays.asList("id1", "id2"))
                .build();

        assertEquals(Arrays.asList("id1", "id2"), filter.getIds());
    }

    @Test
    public void testBuilderWithAuthors() {
        Filter filter = Filter.builder()
                .authors("author1", "author2")
                .build();

        assertEquals(Arrays.asList("author1", "author2"), filter.getAuthors());
    }

    @Test
    public void testBuilderWithKinds() {
        Filter filter = Filter.builder()
                .kinds(1, 4, 7)
                .build();

        assertEquals(Arrays.asList(1, 4, 7), filter.getKinds());
    }

    @Test
    public void testBuilderWithTagFilters() {
        Filter filter = Filter.builder()
                .eTags("event1", "event2")
                .pTags("pubkey1")
                .tTags("topic1", "topic2")
                .dTags("identifier")
                .build();

        assertEquals(Arrays.asList("event1", "event2"), filter.getETags());
        assertEquals(Arrays.asList("pubkey1"), filter.getPTags());
        assertEquals(Arrays.asList("topic1", "topic2"), filter.getTTags());
        assertEquals(Arrays.asList("identifier"), filter.getDTags());
    }

    @Test
    public void testBuilderWithHTags() {
        Filter filter = Filter.builder()
                .hTags("group1", "group2")
                .build();

        assertEquals(Arrays.asList("group1", "group2"), filter.getHTags());
    }

    @Test
    public void testBuilderWithHTagsList() {
        Filter filter = Filter.builder()
                .hTags(Arrays.asList("group1", "group2"))
                .build();

        assertEquals(Arrays.asList("group1", "group2"), filter.getHTags());
    }

    @Test
    public void testBuilderWithTimeRange() {
        Filter filter = Filter.builder()
                .since(1000L)
                .until(2000L)
                .build();

        assertEquals(Long.valueOf(1000L), filter.getSince());
        assertEquals(Long.valueOf(2000L), filter.getUntil());
    }

    @Test
    public void testBuilderWithLimit() {
        Filter filter = Filter.builder()
                .limit(100)
                .build();

        assertEquals(Integer.valueOf(100), filter.getLimit());
    }

    @Test
    public void testBuilderChainAllMethods() {
        Filter filter = Filter.builder()
                .ids("id1")
                .authors("author1")
                .kinds(1)
                .eTags("event1")
                .pTags("pubkey1")
                .tTags("topic1")
                .dTags("d1")
                .hTags("group1")
                .since(1000L)
                .until(2000L)
                .limit(50)
                .build();

        assertEquals(Arrays.asList("id1"), filter.getIds());
        assertEquals(Arrays.asList("author1"), filter.getAuthors());
        assertEquals(Arrays.asList(1), filter.getKinds());
        assertEquals(Arrays.asList("event1"), filter.getETags());
        assertEquals(Arrays.asList("pubkey1"), filter.getPTags());
        assertEquals(Arrays.asList("topic1"), filter.getTTags());
        assertEquals(Arrays.asList("d1"), filter.getDTags());
        assertEquals(Arrays.asList("group1"), filter.getHTags());
        assertEquals(Long.valueOf(1000L), filter.getSince());
        assertEquals(Long.valueOf(2000L), filter.getUntil());
        assertEquals(Integer.valueOf(50), filter.getLimit());
    }

    @Test
    public void testJsonSerializationWithHTags() throws Exception {
        Filter filter = Filter.builder()
                .kinds(9)
                .hTags("my-group")
                .limit(50)
                .build();

        String json = objectMapper.writeValueAsString(filter);

        // Verify JSON contains #h tag
        assertTrue(json.contains("\"#h\""));
        assertTrue(json.contains("my-group"));
        assertTrue(json.contains("\"kinds\":[9]"));
        assertTrue(json.contains("\"limit\":50"));
    }

    @Test
    public void testJsonDeserializationWithHTags() throws Exception {
        String json = "{\"kinds\":[9],\"#h\":[\"group1\",\"group2\"],\"limit\":50}";

        Filter filter = objectMapper.readValue(json, Filter.class);

        assertEquals(Arrays.asList(9), filter.getKinds());
        assertEquals(Arrays.asList("group1", "group2"), filter.getHTags());
        assertEquals(Integer.valueOf(50), filter.getLimit());
    }

    @Test
    public void testNip29GroupMessageFilter() {
        // Real-world example: NIP-29 group message filter
        String groupId = "my-group-id";

        Filter filter = Filter.builder()
                .kinds(9) // NIP-29 group chat message
                .hTags(groupId)
                .limit(50)
                .build();

        assertEquals(Arrays.asList(9), filter.getKinds());
        assertEquals(Arrays.asList(groupId), filter.getHTags());
        assertEquals(Integer.valueOf(50), filter.getLimit());
    }

    @Test
    public void testSettersAndGetters() {
        Filter filter = new Filter();

        filter.setIds(Arrays.asList("id1"));
        filter.setAuthors(Arrays.asList("author1"));
        filter.setKinds(Arrays.asList(1, 4));
        filter.setETags(Arrays.asList("e1"));
        filter.setPTags(Arrays.asList("p1"));
        filter.setTTags(Arrays.asList("t1"));
        filter.setDTags(Arrays.asList("d1"));
        filter.setHTags(Arrays.asList("h1"));
        filter.setSince(1000L);
        filter.setUntil(2000L);
        filter.setLimit(100);

        assertEquals(Arrays.asList("id1"), filter.getIds());
        assertEquals(Arrays.asList("author1"), filter.getAuthors());
        assertEquals(Arrays.asList(1, 4), filter.getKinds());
        assertEquals(Arrays.asList("e1"), filter.getETags());
        assertEquals(Arrays.asList("p1"), filter.getPTags());
        assertEquals(Arrays.asList("t1"), filter.getTTags());
        assertEquals(Arrays.asList("d1"), filter.getDTags());
        assertEquals(Arrays.asList("h1"), filter.getHTags());
        assertEquals(Long.valueOf(1000L), filter.getSince());
        assertEquals(Long.valueOf(2000L), filter.getUntil());
        assertEquals(Integer.valueOf(100), filter.getLimit());
    }
}

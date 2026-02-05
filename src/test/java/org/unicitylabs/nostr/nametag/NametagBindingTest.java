package org.unicitylabs.nostr.nametag;

import org.junit.Test;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;
import org.unicitylabs.nostr.protocol.Filter;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Unit tests for NametagBinding — nametag-to-pubkey mapping.
 */
public class NametagBindingTest {

    // --- createBindingEvent ---

    @Test
    public void testCreateBindingEventStructure() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        Event event = NametagBinding.createBindingEvent(km, "alice", "addr123");

        assertEquals(EventKinds.APP_DATA, event.getKind());
        assertEquals(km.getPublicKeyHex(), event.getPubkey());
        assertNotNull(event.getId());
        assertNotNull(event.getSig());
        assertTrue(event.getId().length() == 64);
        assertTrue(event.getSig().length() == 128);

        // Verify tags
        String expectedHash = NametagUtils.hashNametag("alice", "US");
        assertEquals(expectedHash, event.getTagValue("d"));
        assertEquals(expectedHash, event.getTagValue("nametag"));
        assertEquals(expectedHash, event.getTagValue("t"));
        assertEquals("addr123", event.getTagValue("address"));

        // Verify content is valid JSON
        String content = event.getContent();
        assertTrue(content.contains("nametag_hash"));
        assertTrue(content.contains("address"));
        assertTrue(content.contains("verified"));
        assertTrue(content.contains(expectedHash));
        assertTrue(content.contains("addr123"));
    }

    @Test
    public void testCreateBindingEventWithCustomCountry() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        Event event = NametagBinding.createBindingEvent(km, "+447911123456", "addr123", "GB");

        String expectedHash = NametagUtils.hashNametag("+447911123456", "GB");
        assertEquals(expectedHash, event.getTagValue("d"));
    }

    @Test
    public void testCreateBindingEventDefaultCountryIsUS() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        Event event1 = NametagBinding.createBindingEvent(km, "alice", "addr");
        // The 2-param version uses "US"
        String expectedHash = NametagUtils.hashNametag("alice", "US");
        assertEquals(expectedHash, event1.getTagValue("d"));
    }

    @Test
    public void testBindingEventIsSigned() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        Event event = NametagBinding.createBindingEvent(km, "alice", "addr123");

        // Verify signature
        byte[] eventIdBytes = org.apache.commons.codec.binary.Hex.decodeHex(event.getId().toCharArray());
        assertTrue(NostrKeyManager.verify(
                org.apache.commons.codec.binary.Hex.decodeHex(event.getSig().toCharArray()),
                eventIdBytes,
                km.getPublicKey()
        ));
    }

    @Test
    public void testBindingEventHasCorrectTagCount() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        Event event = NametagBinding.createBindingEvent(km, "alice", "addr123");
        // d, nametag, t, address = 4 tags
        assertEquals(4, event.getTags().size());
    }

    // --- Filter Creation ---

    @Test
    public void testCreateNametagToPubkeyFilter() {
        Filter filter = NametagBinding.createNametagToPubkeyFilter("alice");

        assertNotNull(filter.getKinds());
        assertEquals(Arrays.asList(EventKinds.APP_DATA), filter.getKinds());

        String expectedHash = NametagUtils.hashNametag("alice", "US");
        assertNotNull(filter.getTTags());
        assertEquals(Arrays.asList(expectedHash), filter.getTTags());

        assertEquals(Integer.valueOf(1), filter.getLimit());
    }

    @Test
    public void testCreateNametagToPubkeyFilterWithCustomCountry() {
        Filter filter = NametagBinding.createNametagToPubkeyFilter("+447911123456", "GB");

        String expectedHash = NametagUtils.hashNametag("+447911123456", "GB");
        assertEquals(Arrays.asList(expectedHash), filter.getTTags());
    }

    @Test
    public void testCreatePubkeyToNametagFilter() {
        Filter filter = NametagBinding.createPubkeyToNametagFilter("abc123def456");

        assertEquals(Arrays.asList(EventKinds.APP_DATA), filter.getKinds());
        assertEquals(Arrays.asList("abc123def456"), filter.getAuthors());
        assertEquals(Integer.valueOf(10), filter.getLimit());
    }

    // --- parseNametagHashFromEvent ---

    @Test
    public void testParseNametagHashFromTag() {
        Event event = new Event();
        event.setKind(EventKinds.APP_DATA);
        event.setTags(Arrays.asList(
                Arrays.asList("nametag", "hashvalue123")
        ));
        event.setContent("{}");

        assertEquals("hashvalue123", NametagBinding.parseNametagHashFromEvent(event));
    }

    @Test
    public void testParseNametagHashFallsBackToContentJson() {
        Event event = new Event();
        event.setKind(EventKinds.APP_DATA);
        // No nametag tag
        event.setContent("{\"nametag_hash\":\"hash_from_content\"}");

        assertEquals("hash_from_content", NametagBinding.parseNametagHashFromEvent(event));
    }

    @Test
    public void testParseNametagHashFromNullEvent() {
        assertNull(NametagBinding.parseNametagHashFromEvent(null));
    }

    @Test
    public void testParseNametagHashFromWrongKind() {
        Event event = new Event();
        event.setKind(EventKinds.TEXT_NOTE); // Wrong kind
        event.setTags(Arrays.asList(Arrays.asList("nametag", "hash")));

        assertNull(NametagBinding.parseNametagHashFromEvent(event));
    }

    @Test
    public void testParseNametagHashNoTagNoValidContent() {
        Event event = new Event();
        event.setKind(EventKinds.APP_DATA);
        event.setContent("invalid json");

        assertNull(NametagBinding.parseNametagHashFromEvent(event));
    }

    // --- parseAddressFromEvent ---

    @Test
    public void testParseAddressFromTag() {
        Event event = new Event();
        event.setKind(EventKinds.APP_DATA);
        event.setTags(Arrays.asList(
                Arrays.asList("address", "unicity_addr_123")
        ));
        event.setContent("{}");

        assertEquals("unicity_addr_123", NametagBinding.parseAddressFromEvent(event));
    }

    @Test
    public void testParseAddressFallsBackToContentJson() {
        Event event = new Event();
        event.setKind(EventKinds.APP_DATA);
        event.setContent("{\"address\":\"addr_from_json\"}");

        assertEquals("addr_from_json", NametagBinding.parseAddressFromEvent(event));
    }

    @Test
    public void testParseAddressFromNullEvent() {
        assertNull(NametagBinding.parseAddressFromEvent(null));
    }

    @Test
    public void testParseAddressFromWrongKind() {
        Event event = new Event();
        event.setKind(EventKinds.TEXT_NOTE);
        assertNull(NametagBinding.parseAddressFromEvent(event));
    }

    // --- Integration: create and parse ---

    @Test
    public void testCreateAndParseBindingEvent() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        Event event = NametagBinding.createBindingEvent(km, "alice", "addr_123");

        String hash = NametagBinding.parseNametagHashFromEvent(event);
        String address = NametagBinding.parseAddressFromEvent(event);

        assertEquals(NametagUtils.hashNametag("alice"), hash);
        assertEquals("addr_123", address);
    }
}

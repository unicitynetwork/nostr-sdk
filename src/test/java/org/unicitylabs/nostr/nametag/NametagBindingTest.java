package org.unicitylabs.nostr.nametag;

import org.junit.Before;
import org.junit.Test;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;
import org.unicitylabs.nostr.protocol.Filter;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

/**
 * Unit tests for NametagBinding - mirrors JS nostr-js-sdk nametag.test.ts
 */
public class NametagBindingTest {

    private NostrKeyManager keyManager;

    @Before
    public void setUp() {
        keyManager = NostrKeyManager.generate();
    }

    // =========================================================================
    // createBindingEvent
    // =========================================================================

    @Test
    public void shouldCreateSignedEvent() throws Exception {
        Event event = NametagBinding.createBindingEvent(keyManager, "alice", "unicity_address_123");
        assertNotNull(event.getId());
        assertNotNull(event.getSig());
        assertEquals(keyManager.getPublicKeyHex(), event.getPubkey());
        assertEquals(EventKinds.APP_DATA, event.getKind());
        assertTrue(event.verify());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectTooShortNametag() throws Exception {
        NametagBinding.createBindingEvent(keyManager, "ab", "addr");
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectEmptyNametag() throws Exception {
        NametagBinding.createBindingEvent(keyManager, "", "addr");
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectTooLongNametag() throws Exception {
        NametagBinding.createBindingEvent(keyManager, "aaaaaaaaaaaaaaaaaaaaa", "addr"); // 21 chars
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectInvalidCharacters() throws Exception {
        NametagBinding.createBindingEvent(keyManager, "foo.bar", "addr");
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectSpacesInNametag() throws Exception {
        NametagBinding.createBindingEvent(keyManager, "hello world", "addr");
    }

    @Test
    public void shouldAcceptValidPhoneNumbers() throws Exception {
        Event event = NametagBinding.createBindingEvent(keyManager, "+14155552671", "addr");
        assertTrue(event.verify());
    }

    @Test
    public void shouldIncludeRequiredTags() throws Exception {
        Event event = NametagBinding.createBindingEvent(keyManager, "alice", "unicity_address_123");

        assertNotNull(event.getTagValue("d"));
        assertNotNull(event.getTagValue("nametag"));
        assertNotNull(event.getTagValue("t"));
        assertNotNull(event.getTagValue("address"));
        assertEquals("unicity_address_123", event.getTagValue("address"));
    }

    @Test
    public void shouldIncludeHashedAddressTTag() throws Exception {
        Event event = NametagBinding.createBindingEvent(keyManager, "alice", "unicity_address_123");

        String expectedHash = NametagUtils.hashAddressForTag("unicity_address_123");
        List<String> tTags = event.getTags().stream()
            .filter(t -> "t".equals(t.get(0)))
            .map(t -> t.get(1))
            .collect(Collectors.toList());
        assertTrue(tTags.contains(expectedHash));
    }

    @Test
    public void shouldIncludeContentWithHashAndAddress() throws Exception {
        Event event = NametagBinding.createBindingEvent(keyManager, "alice", "unicity_address_123");
        String content = event.getContent();
        assertTrue(content.contains("nametag_hash"));
        assertTrue(content.contains("unicity_address_123"));
        assertTrue(content.contains("verified"));
    }

    @Test
    public void shouldIncludeIdentityFieldsInContentAndTags() throws Exception {
        NametagBinding.IdentityBindingParams identity = new NametagBinding.IdentityBindingParams(
            "02" + "a".repeat(64),
            "alpha1testaddr",
            "DIRECT://test",
            "PROXY://test"
        );

        Event event = NametagBinding.createBindingEvent(keyManager, "alice", "unicity_address_123", "US", identity);

        // Content should have identity fields
        String content = event.getContent();
        assertTrue(content.contains("02" + "a".repeat(64)));
        assertTrue(content.contains("alpha1testaddr"));
        assertTrue(content.contains("DIRECT://test"));
        assertTrue(content.contains("PROXY://test"));
        assertTrue(content.contains("\"nametag\":\"alice\""));
        assertTrue(content.contains("encrypted_nametag"));

        // Tags should have hashed t-tags for each address
        List<String> tTags = event.getTags().stream()
            .filter(t -> "t".equals(t.get(0)))
            .map(t -> t.get(1))
            .collect(Collectors.toList());
        assertTrue(tTags.contains(NametagUtils.hashAddressForTag(identity.getPublicKey())));
        assertTrue(tTags.contains(NametagUtils.hashAddressForTag(identity.getL1Address())));
        assertTrue(tTags.contains(NametagUtils.hashAddressForTag(identity.getDirectAddress())));
        assertTrue(tTags.contains(NametagUtils.hashAddressForTag(identity.getProxyAddress())));

        // Backward-compat plaintext tags
        assertEquals(identity.getPublicKey(), event.getTagValue("pubkey"));
        assertEquals(identity.getL1Address(), event.getTagValue("l1"));
    }

    // =========================================================================
    // createIdentityBindingEvent
    // =========================================================================

    @Test
    public void shouldCreateIdentityEventWithDTag() throws Exception {
        NametagBinding.IdentityBindingParams identity = new NametagBinding.IdentityBindingParams(
            "02" + "a".repeat(64), "alpha1test", "DIRECT://test", null
        );

        Event event = NametagBinding.createIdentityBindingEvent(keyManager, identity);

        assertEquals(EventKinds.APP_DATA, event.getKind());
        assertTrue(event.verify());

        String expectedDTag = NametagUtils.sha256Hex("unicity:identity:" + keyManager.getPublicKeyHex());
        assertEquals(expectedDTag, event.getTagValue("d"));
    }

    @Test
    public void shouldIncludeHashedTTagsForAllAddresses() throws Exception {
        NametagBinding.IdentityBindingParams identity = new NametagBinding.IdentityBindingParams(
            "02" + "b".repeat(64), "alpha1xyz", "DIRECT://xyz", null
        );

        Event event = NametagBinding.createIdentityBindingEvent(keyManager, identity);
        List<String> tTags = event.getTags().stream()
            .filter(t -> "t".equals(t.get(0)))
            .map(t -> t.get(1))
            .collect(Collectors.toList());

        assertTrue(tTags.contains(NametagUtils.hashAddressForTag(identity.getPublicKey())));
        assertTrue(tTags.contains(NametagUtils.hashAddressForTag(identity.getL1Address())));
        assertTrue(tTags.contains(NametagUtils.hashAddressForTag(identity.getDirectAddress())));
    }

    @Test
    public void shouldIncludeIdentityFieldsInContent() throws Exception {
        NametagBinding.IdentityBindingParams identity = new NametagBinding.IdentityBindingParams(
            "02" + "c".repeat(64), "alpha1abc", "DIRECT://abc", null
        );

        Event event = NametagBinding.createIdentityBindingEvent(keyManager, identity);
        String content = event.getContent();
        assertTrue(content.contains(identity.getPublicKey()));
        assertTrue(content.contains(identity.getL1Address()));
        assertTrue(content.contains(identity.getDirectAddress()));
    }

    @Test
    public void shouldNotIncludeNametagOrEncryptedNametagInIdentityEvent() throws Exception {
        NametagBinding.IdentityBindingParams identity = new NametagBinding.IdentityBindingParams(
            "02" + "d".repeat(64), null, null, null
        );

        Event event = NametagBinding.createIdentityBindingEvent(keyManager, identity);
        String content = event.getContent();
        assertFalse(content.contains("nametag"));
        assertFalse(content.contains("encrypted_nametag"));
        assertFalse(content.contains("nametag_hash"));
    }

    // =========================================================================
    // createNametagToPubkeyFilter
    // =========================================================================

    @Test
    public void shouldCreateFilterWithHashedNametag() {
        Filter filter = NametagBinding.createNametagToPubkeyFilter("alice");
        assertNotNull(filter.getKinds());
        assertTrue(filter.getKinds().contains(EventKinds.APP_DATA));
        assertNotNull(filter.getTTags());
        assertTrue(filter.getTTags().contains(NametagUtils.hashNametag("alice")));
    }

    @Test
    public void shouldNotSetLimitOnNametagFilter() {
        Filter filter = NametagBinding.createNametagToPubkeyFilter("alice");
        assertNull(filter.getLimit());
    }

    // =========================================================================
    // createAddressToBindingFilter
    // =========================================================================

    @Test
    public void shouldCreateFilterWithHashedAddress() {
        String address = "DIRECT://test123";
        Filter filter = NametagBinding.createAddressToBindingFilter(address);
        assertNotNull(filter.getKinds());
        assertTrue(filter.getKinds().contains(EventKinds.APP_DATA));
        assertNotNull(filter.getTTags());
        assertTrue(filter.getTTags().contains(NametagUtils.hashAddressForTag(address)));
    }

    @Test
    public void shouldNotSetLimitOnAddressFilter() {
        Filter filter = NametagBinding.createAddressToBindingFilter("alpha1test");
        assertNull(filter.getLimit());
    }

    // =========================================================================
    // createPubkeyToNametagFilter
    // =========================================================================

    @Test
    public void shouldCreateFilterWithAuthorPubkey() {
        String pubkey = keyManager.getPublicKeyHex();
        Filter filter = NametagBinding.createPubkeyToNametagFilter(pubkey);
        assertNotNull(filter.getAuthors());
        assertTrue(filter.getAuthors().contains(pubkey));
        assertNotNull(filter.getLimit());
        assertEquals(Integer.valueOf(10), filter.getLimit());
    }

    // =========================================================================
    // parseBindingInfo
    // =========================================================================

    @Test
    public void shouldParseBasicFieldsFromEventContent() throws Exception {
        Event event = NametagBinding.createBindingEvent(keyManager, "alice", "unicity_address_123");

        NametagBinding.BindingInfo info = NametagBinding.parseBindingInfo(event);
        assertEquals(keyManager.getPublicKeyHex(), info.getTransportPubkey());
        assertEquals(event.getCreatedAt() * 1000, info.getTimestamp());
    }

    @Test
    public void shouldParseExtendedIdentityFields() throws Exception {
        NametagBinding.IdentityBindingParams identity = new NametagBinding.IdentityBindingParams(
            "02" + "a".repeat(64), "alpha1testaddr", "DIRECT://test", "PROXY://test"
        );

        Event event = NametagBinding.createBindingEvent(keyManager, "alice", "unicity_address_123", "US", identity);

        NametagBinding.BindingInfo info = NametagBinding.parseBindingInfo(event);
        assertEquals(identity.getPublicKey(), info.getPublicKey());
        assertEquals(identity.getL1Address(), info.getL1Address());
        assertEquals(identity.getDirectAddress(), info.getDirectAddress());
        assertEquals(identity.getProxyAddress(), info.getProxyAddress());
        assertEquals("alice", info.getNametag());
    }

    @Test
    public void shouldReturnMinimalInfoWhenContentIsInvalidJson() {
        Event event = new Event();
        event.setPubkey(keyManager.getPublicKeyHex());
        event.setCreatedAt(1000);
        event.setKind(EventKinds.APP_DATA);
        event.setContent("not valid json");

        NametagBinding.BindingInfo info = NametagBinding.parseBindingInfo(event);
        assertEquals(keyManager.getPublicKeyHex(), info.getTransportPubkey());
        assertEquals(1000L * 1000, info.getTimestamp());
        assertNull(info.getPublicKey());
        assertNull(info.getNametag());
    }

    // =========================================================================
    // parseNametagHashFromEvent / parseAddressFromEvent
    // =========================================================================

    @Test
    public void shouldParseNametagHashFromTags() throws Exception {
        Event event = NametagBinding.createBindingEvent(keyManager, "alice", "addr");
        String hash = NametagBinding.parseNametagHashFromEvent(event);
        assertNotNull(hash);
        assertEquals(NametagUtils.hashNametag("alice"), hash);
    }

    @Test
    public void shouldParseAddressFromTags() throws Exception {
        Event event = NametagBinding.createBindingEvent(keyManager, "alice", "unicity_addr_123");
        String address = NametagBinding.parseAddressFromEvent(event);
        assertEquals("unicity_addr_123", address);
    }
}

package org.unicitylabs.nostr.client;

import org.junit.Test;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Unit tests for NIP-42 Client Authentication.
 */
public class NIP42AuthTest {

    @Test
    public void testAuthEventKindValue() {
        assertEquals(22242, EventKinds.AUTH);
    }

    @Test
    public void testAuthIsEphemeral() {
        // NIP-42 AUTH events are ephemeral (kind 20000-29999)
        assertTrue(EventKinds.isEphemeral(EventKinds.AUTH));
    }

    @Test
    public void testAuthEventKindName() {
        assertEquals("Auth", EventKinds.getName(EventKinds.AUTH));
    }

    @Test
    public void testCreateAuthEvent() {
        NostrKeyManager keyManager = NostrKeyManager.generate();
        String relayUrl = "wss://relay.example.com";
        String challenge = "test-challenge-12345";

        Event authEvent = new Event();
        authEvent.setPubkey(keyManager.getPublicKeyHex());
        authEvent.setCreatedAt(System.currentTimeMillis() / 1000);
        authEvent.setKind(EventKinds.AUTH);
        authEvent.setTags(Arrays.asList(
            Arrays.asList("relay", relayUrl),
            Arrays.asList("challenge", challenge)
        ));
        authEvent.setContent("");

        assertEquals(22242, authEvent.getKind());
        assertEquals("", authEvent.getContent());
        assertEquals(keyManager.getPublicKeyHex(), authEvent.getPubkey());

        // Check tags
        List<List<String>> tags = authEvent.getTags();
        assertEquals(2, tags.size());
        assertEquals(Arrays.asList("relay", relayUrl), tags.get(0));
        assertEquals(Arrays.asList("challenge", challenge), tags.get(1));
    }

    @Test
    public void testAuthEventTagAccess() {
        Event authEvent = new Event();
        authEvent.setTags(Arrays.asList(
            Arrays.asList("relay", "wss://test.relay"),
            Arrays.asList("challenge", "abc123")
        ));

        assertEquals("wss://test.relay", authEvent.getTagValue("relay"));
        assertEquals("abc123", authEvent.getTagValue("challenge"));
        assertTrue(authEvent.hasTag("relay"));
        assertTrue(authEvent.hasTag("challenge"));
        assertFalse(authEvent.hasTag("other"));
    }

    @Test
    public void testAuthEventContentIsEmpty() {
        // NIP-42 auth events should have empty content
        Event authEvent = new Event();
        authEvent.setKind(EventKinds.AUTH);
        authEvent.setContent("");

        assertEquals("", authEvent.getContent());
    }

    @Test
    public void testAuthEventRequiredTags() {
        // Verify AUTH event structure matches NIP-42 spec
        NostrKeyManager keyManager = NostrKeyManager.generate();
        String relayUrl = "wss://relay.example.com";
        String challenge = "challenge-string";

        Event authEvent = new Event();
        authEvent.setPubkey(keyManager.getPublicKeyHex());
        authEvent.setCreatedAt(System.currentTimeMillis() / 1000);
        authEvent.setKind(EventKinds.AUTH);
        authEvent.setTags(Arrays.asList(
            Arrays.asList("relay", relayUrl),
            Arrays.asList("challenge", challenge)
        ));
        authEvent.setContent("");

        // NIP-42 requires: relay tag and challenge tag
        assertNotNull(authEvent.getTagValue("relay"));
        assertNotNull(authEvent.getTagValue("challenge"));
        assertEquals(relayUrl, authEvent.getTagValue("relay"));
        assertEquals(challenge, authEvent.getTagValue("challenge"));
    }
}

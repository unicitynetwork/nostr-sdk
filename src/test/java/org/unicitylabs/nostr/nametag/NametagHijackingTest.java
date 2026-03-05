package org.unicitylabs.nostr.nametag;

import org.junit.Test;
import org.unicitylabs.nostr.client.NostrClient;
import org.unicitylabs.nostr.client.NostrEventListener;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.Filter;

import java.util.concurrent.CompletableFuture;

import static org.junit.Assert.*;

/**
 * Tests for nametag hijacking prevention.
 *
 * Verifies the two core anti-hijacking mechanisms:
 * 1. First-seen-wins: queryPubkeyByNametag returns the earliest binding author
 * 2. Conflict detection: publishNametagBinding rejects if nametag is claimed by another pubkey
 *
 * These tests use a FakeNostrClient that overrides subscribe() to deliver
 * predetermined events, allowing us to test the resolution logic in isolation.
 */
public class NametagHijackingTest {

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Create a signed binding event for a nametag from a given key manager,
     * with an overridden created_at timestamp.
     */
    private static Event createSignedBinding(NostrKeyManager km, String nametag, long createdAt) throws Exception {
        Event event = NametagBinding.createBindingEvent(km, nametag, km.getPublicKeyHex());
        // Override created_at and re-sign to create a valid event at a specific timestamp
        event.setCreatedAt(createdAt);
        // Re-calculate ID and re-sign since we changed created_at
        resignEvent(km, event);
        return event;
    }

    /**
     * Re-calculate ID and re-sign an event after modification.
     */
    private static void resignEvent(NostrKeyManager km, Event event) throws Exception {
        // Use reflection-free approach: recalculate via NametagBinding's internal method
        // We build the event manually
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        java.util.List<Object> eventData = java.util.Arrays.asList(
            0, event.getPubkey(), event.getCreatedAt(), event.getKind(), event.getTags(), event.getContent()
        );
        String eventJson = mapper.writeValueAsString(eventData);
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(eventJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String eventId = new String(org.apache.commons.codec.binary.Hex.encodeHex(hashBytes));
        event.setId(eventId);
        byte[] eventIdBytes = org.apache.commons.codec.binary.Hex.decodeHex(eventId.toCharArray());
        String signature = km.signHex(eventIdBytes);
        event.setSig(signature);
    }

    /**
     * A test subclass of NostrClient that overrides subscribe to deliver
     * predetermined events. This lets us test the query resolution logic
     * without needing actual relay connections.
     */
    private static class FakeNostrClient extends NostrClient {
        private Event[] eventsToDeliver;

        FakeNostrClient(NostrKeyManager km) {
            super(km);
            setQueryTimeoutMs(1000);
        }

        void setEventsToDeliver(Event... events) {
            this.eventsToDeliver = events;
        }

        @Override
        public String subscribe(String subscriptionId, Filter filter, NostrEventListener listener) {
            // Don't actually connect to any relay, just deliver events immediately
            CompletableFuture.runAsync(() -> {
                if (eventsToDeliver != null) {
                    for (Event event : eventsToDeliver) {
                        listener.onEvent(event);
                    }
                }
                listener.onEndOfStoredEvents(subscriptionId);
            });
            return subscriptionId;
        }

        @Override
        public String subscribe(Filter filter, NostrEventListener listener) {
            String subscriptionId = "test-sub-" + System.nanoTime();
            return subscribe(subscriptionId, filter, listener);
        }
    }

    // =========================================================================
    // First-seen-wins: queryPubkeyByNametag
    // =========================================================================

    @Test
    public void shouldReturnPubkeyOfEarliestBindingEvent() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event aliceEvent = createSignedBinding(alice, "coolname", 1000);
        Event bobEvent = createSignedBinding(bob, "coolname", 2000);

        FakeNostrClient client = new FakeNostrClient(alice);
        // Relay returns both events (order doesn't matter — code picks earliest)
        client.setEventsToDeliver(bobEvent, aliceEvent);

        String owner = client.queryPubkeyByNametag("coolname").get();
        assertEquals(alice.getPublicKeyHex(), owner);
    }

    @Test
    public void shouldPickEarliestEvenWhenAttackerEventArrivesFirst() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event aliceEvent = createSignedBinding(alice, "target", 1000);
        Event bobEvent = createSignedBinding(bob, "target", 2000);

        FakeNostrClient client = new FakeNostrClient(alice);
        // Bob's event arrives first
        client.setEventsToDeliver(bobEvent, aliceEvent);

        String owner = client.queryPubkeyByNametag("target").get();
        assertEquals(alice.getPublicKeyHex(), owner);
        assertNotEquals(bob.getPublicKeyHex(), owner);
    }

    @Test
    public void shouldReturnNullWhenNoBindingExists() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(); // no events

        String owner = client.queryPubkeyByNametag("unclaimed").get();
        assertNull(owner);
    }

    @Test
    public void shouldReturnOnlyPubkeyWhenSingleBinding() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        Event aliceEvent = createSignedBinding(alice, "solo", 1000);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(aliceEvent);

        String owner = client.queryPubkeyByNametag("solo").get();
        assertEquals(alice.getPublicKeyHex(), owner);
    }

    @Test
    public void shouldHandleMultipleHijackAttemptsAndReturnOriginalOwner() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager attacker1 = NostrKeyManager.generate();
        NostrKeyManager attacker2 = NostrKeyManager.generate();

        Event aliceEvent = createSignedBinding(alice, "popular", 1000);
        Event attack1Event = createSignedBinding(attacker1, "popular", 1500);
        Event attack2Event = createSignedBinding(attacker2, "popular", 2000);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(attack2Event, attack1Event, aliceEvent);

        String owner = client.queryPubkeyByNametag("popular").get();
        assertEquals(alice.getPublicKeyHex(), owner);
    }

    // =========================================================================
    // First-seen-wins: queryBindingByNametag
    // =========================================================================

    @Test
    public void shouldReturnBindingInfoFromEarliestEvent() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event aliceEvent = createSignedBinding(alice, "richinfo", 1000);
        Event bobEvent = createSignedBinding(bob, "richinfo", 2000);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(bobEvent, aliceEvent);

        NametagBinding.BindingInfo info = client.queryBindingByNametag("richinfo").get();
        assertNotNull(info);
        assertEquals(alice.getPublicKeyHex(), info.getTransportPubkey());
        assertEquals(1000L * 1000, info.getTimestamp());
    }

    @Test
    public void shouldReturnNullBindingInfoWhenNoBindingExists() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver();

        NametagBinding.BindingInfo info = client.queryBindingByNametag("ghost").get();
        assertNull(info);
    }

    // =========================================================================
    // Same-author latest-wins
    // =========================================================================

    @Test
    public void shouldReturnLatestEventFromRightfulOwner() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();

        Event aliceOld = createSignedBinding(alice, "evolving", 1000);
        Event aliceNew = createSignedBinding(alice, "evolving", 2000);
        // Modify content to distinguish
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        java.util.Map<String, Object> newContent = new java.util.LinkedHashMap<>();
        newContent.put("nametag_hash", "hash");
        newContent.put("address", alice.getPublicKeyHex());
        newContent.put("verified", System.currentTimeMillis() / 1000);
        newContent.put("nametag", "evolving");
        newContent.put("l1_address", "alpha1updated");
        aliceNew.setContent(mapper.writeValueAsString(newContent));
        resignEvent(alice, aliceNew);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(aliceOld, aliceNew);

        NametagBinding.BindingInfo info = client.queryBindingByNametag("evolving").get();
        assertNotNull(info);
        assertEquals(alice.getPublicKeyHex(), info.getTransportPubkey());
        // Should return the LATEST event's data (timestamp 2000)
        assertEquals(2000L * 1000, info.getTimestamp());
        assertEquals("alpha1updated", info.getL1Address());
    }

    @Test
    public void shouldReturnLatestSameAuthorEvenWhenAttackerPresent() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event aliceOld = createSignedBinding(alice, "contested", 1000);
        Event aliceNew = createSignedBinding(alice, "contested", 3000);
        Event bobEvent = createSignedBinding(bob, "contested", 2000);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(bobEvent, aliceNew, aliceOld);

        NametagBinding.BindingInfo info = client.queryBindingByNametag("contested").get();
        assertNotNull(info);
        // Alice wins (earliest first-seen = 1000)
        assertEquals(alice.getPublicKeyHex(), info.getTransportPubkey());
        // But we get Alice's LATEST event (timestamp 3000)
        assertEquals(3000L * 1000, info.getTimestamp());
    }

    @Test
    public void shouldPickEarliestAuthorWithMultipleSameAuthorEvents() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event alice1 = createSignedBinding(alice, "multiauth", 1000);
        Event alice2 = createSignedBinding(alice, "multiauth", 3000);
        Event bobEvent = createSignedBinding(bob, "multiauth", 2000);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(alice2, bobEvent, alice1);

        String owner = client.queryPubkeyByNametag("multiauth").get();
        // Alice first appeared at 1000, Bob at 2000 → Alice wins
        assertEquals(alice.getPublicKeyHex(), owner);
    }

    // =========================================================================
    // queryBindingByAddress (reverse lookup)
    // =========================================================================

    @Test
    public void shouldReturnLatestEventFromSameAuthorByAddress() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();

        Event bareEvent = createSignedBinding(alice, "lookup", 1000);
        Event fullEvent = createSignedBinding(alice, "lookup", 2000);

        // Modify content for the full event
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        java.util.Map<String, Object> newContent = new java.util.LinkedHashMap<>();
        newContent.put("nametag_hash", "hash");
        newContent.put("address", alice.getPublicKeyHex());
        newContent.put("verified", System.currentTimeMillis() / 1000);
        newContent.put("nametag", "lookup");
        newContent.put("l1_address", "alpha1full");
        newContent.put("direct_address", "DIRECT://full");
        fullEvent.setContent(mapper.writeValueAsString(newContent));
        resignEvent(alice, fullEvent);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(bareEvent, fullEvent);

        NametagBinding.BindingInfo info = client.queryBindingByAddress(alice.getPublicKeyHex()).get();
        assertNotNull(info);
        assertEquals(2000L * 1000, info.getTimestamp());
        assertEquals("lookup", info.getNametag());
        assertEquals("alpha1full", info.getL1Address());
    }

    // =========================================================================
    // Conflict detection: publishNametagBinding
    // =========================================================================

    @Test
    public void shouldRejectWhenNametagClaimedByAnotherPubkey() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event aliceEvent = createSignedBinding(alice, "taken", 1000);

        // Bob's client queries the relay → finds Alice's binding
        FakeNostrClient bobClient = new FakeNostrClient(bob);
        bobClient.setEventsToDeliver(aliceEvent);

        try {
            bobClient.publishNametagBinding("taken", bob.getPublicKeyHex()).get();
            fail("Expected exception for already claimed nametag");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("already claimed") || e.getCause().getMessage().contains("already claimed"));
        }
    }

    @Test
    public void shouldSucceedWhenNametagIsUnclaimed() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();

        // No events on relay, and publishEvent succeeds
        FakeNostrClient client = new FakeNostrClient(alice) {
            @Override
            public CompletableFuture<String> publishEvent(Event event) {
                return CompletableFuture.completedFuture("event-id");
            }
        };
        client.setEventsToDeliver(); // no events

        Boolean result = client.publishNametagBinding("fresh", alice.getPublicKeyHex()).get();
        assertTrue(result);
    }

    @Test
    public void shouldSucceedWhenSamePubkeyRepublishes() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();

        Event aliceEvent = createSignedBinding(alice, "mine", 1000);

        FakeNostrClient client = new FakeNostrClient(alice) {
            @Override
            public CompletableFuture<String> publishEvent(Event event) {
                return CompletableFuture.completedFuture("event-id");
            }
        };
        client.setEventsToDeliver(aliceEvent);

        Boolean result = client.publishNametagBinding("mine", alice.getPublicKeyHex()).get();
        assertTrue(result);
    }

    // =========================================================================
    // End-to-end hijacking scenario
    // =========================================================================

    @Test
    public void aliceRegistersBobTriesToHijackResolutionStillReturnsAlice() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event aliceEvent = createSignedBinding(alice, "alice", 1000);
        Event bobEvent = createSignedBinding(bob, "alice", 2000);

        // Any client resolving "alice" should get Alice's pubkey (earliest)
        NostrKeyManager resolver = NostrKeyManager.generate();
        FakeNostrClient resolverClient = new FakeNostrClient(resolver);
        resolverClient.setEventsToDeliver(bobEvent, aliceEvent);

        String resolvedPubkey = resolverClient.queryPubkeyByNametag("alice").get();
        assertEquals(alice.getPublicKeyHex(), resolvedPubkey);
        assertNotEquals(bob.getPublicKeyHex(), resolvedPubkey);
    }

    @Test
    public void bobCannotPublishIfAliceAlreadyClaimedNametag() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event aliceEvent = createSignedBinding(alice, "protected", 1000);

        // Bob's client sees Alice's existing binding
        FakeNostrClient bobClient = new FakeNostrClient(bob);
        bobClient.setEventsToDeliver(aliceEvent);

        try {
            bobClient.publishNametagBinding("protected", bob.getPublicKeyHex()).get();
            fail("Expected exception for already claimed nametag");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("already claimed") || e.getCause().getMessage().contains("already claimed"));
        }

        // Resolution still returns Alice
        String owner = bobClient.queryPubkeyByNametag("protected").get();
        assertEquals(alice.getPublicKeyHex(), owner);
    }
}

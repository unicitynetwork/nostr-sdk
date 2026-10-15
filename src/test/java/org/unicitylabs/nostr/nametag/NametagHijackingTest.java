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
 * 1. No guessing between authors: when more than one author publishes a legacy
 *    (unmarked) binding for a nametag, resolution returns null — created_at is
 *    self-asserted, so it never picks a winner
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
        // These tests exercise the LEGACY (unmarked) resolution path, where a
        // single author resolves and several authors are ambiguous. Strip the
        // UNIP-01 marker so the events take that path; the marked (UNIP-01) path is covered by the
        // createMarkedBinding tests below.
        event.setTags(stripMarker(event.getTags()));
        // Override created_at and re-sign to create a valid event at a specific timestamp
        event.setCreatedAt(createdAt);
        // Re-calculate ID and re-sign since we changed created_at
        resignEvent(km, event);
        return event;
    }

    /** Remove the UNIP-01 ["L", ...] marker tag(s) to simulate a legacy/unmarked binding. */
    private static java.util.List<java.util.List<String>> stripMarker(java.util.List<java.util.List<String>> tags) {
        java.util.List<java.util.List<String>> out = new java.util.ArrayList<>();
        for (java.util.List<String> tag : tags) {
            if (!(tag.size() >= 1 && "L".equals(tag.get(0)))) {
                out.add(tag);
            }
        }
        return out;
    }

    /**
     * Create a MARKED (UNIP-01) binding at a specific created_at. createBindingEvent
     * emits the marker; we keep it and re-sign so the marked resolution path is used.
     */
    private static Event createMarkedBinding(NostrKeyManager km, String nametag, long createdAt) throws Exception {
        Event event = NametagBinding.createBindingEvent(km, nametag, km.getPublicKeyHex());
        event.setCreatedAt(createdAt);
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
    // Ambiguity: queryPubkeyByNametag
    // =========================================================================

    @Test
    public void shouldReturnNullWhenTwoAuthorsPublishLegacyBindings() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // Alice's binding says 1000, Bob's says 2000 — but both are
        // self-asserted, and Bob could just as well have claimed 1.
        Event aliceEvent = createSignedBinding(alice, "coolname", 1000);
        Event bobEvent = createSignedBinding(bob, "coolname", 2000);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(bobEvent, aliceEvent);

        String owner = client.queryPubkeyByNametag("coolname").get();
        assertNull(owner);
    }

    @Test
    public void shouldReturnNullWhateverTheDeliveryOrder() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event aliceEvent = createSignedBinding(alice, "target", 1000);
        Event bobEvent = createSignedBinding(bob, "target", 2000);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(aliceEvent, bobEvent);

        String owner = client.queryPubkeyByNametag("target").get();
        assertNull(owner);
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
    public void shouldReturnNullUnderMultipleCompetingLegacyBindings() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager attacker1 = NostrKeyManager.generate();
        NostrKeyManager attacker2 = NostrKeyManager.generate();

        Event aliceEvent = createSignedBinding(alice, "popular", 1000);
        Event attack1Event = createSignedBinding(attacker1, "popular", 1500);
        Event attack2Event = createSignedBinding(attacker2, "popular", 2000);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(attack2Event, attack1Event, aliceEvent);

        String owner = client.queryPubkeyByNametag("popular").get();
        assertNull(owner);
    }

    // =========================================================================
    // queryBindingByNametag
    // =========================================================================

    @Test
    public void shouldReturnBindingInfoFromOnlyAuthor() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();

        Event aliceEvent = createSignedBinding(alice, "richinfo", 1000);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(aliceEvent);

        NametagBinding.BindingInfo info = client.queryBindingByNametag("richinfo").get();
        assertNotNull(info);
        assertEquals(alice.getPublicKeyHex(), info.getTransportPubkey());
        assertEquals(1000L * 1000, info.getTimestamp());
    }

    @Test
    public void shouldReturnNullBindingInfoWhenTwoAuthorsPublishLegacyBindings() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event aliceEvent = createSignedBinding(alice, "richinfo", 1000);
        Event bobEvent = createSignedBinding(bob, "richinfo", 2000);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(bobEvent, aliceEvent);

        assertNull(client.queryBindingByNametag("richinfo").get());
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
    public void shouldReturnNullWhenAnotherAuthorIsAlsoPresent() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // Alice: old binding at 1000, updated at 3000; Bob's binding says 2000.
        Event aliceOld = createSignedBinding(alice, "contested", 1000);
        Event aliceNew = createSignedBinding(alice, "contested", 3000);
        Event bobEvent = createSignedBinding(bob, "contested", 2000);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(bobEvent, aliceNew, aliceOld);

        // Alice's extra event does not make her more of an owner: two authors.
        assertNull(client.queryBindingByNametag("contested").get());
    }

    @Test
    public void shouldResolveOneAuthorWithSeveralEvents() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();

        Event alice1 = createSignedBinding(alice, "multiauth", 1000);
        Event alice2 = createSignedBinding(alice, "multiauth", 3000);

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(alice2, alice1);

        String owner = client.queryPubkeyByNametag("multiauth").get();
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
    public void shouldRejectWhenTwoOtherAuthorsContestNametag() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();
        NostrKeyManager carol = NostrKeyManager.generate();

        // Contested resolves to null, but null here does not mean "available".
        Event aliceEvent = createSignedBinding(alice, "contested", 1000);
        Event bobEvent = createSignedBinding(bob, "contested", 2000);

        java.util.concurrent.atomic.AtomicBoolean published = new java.util.concurrent.atomic.AtomicBoolean();
        FakeNostrClient carolClient = new FakeNostrClient(carol) {
            @Override
            public CompletableFuture<String> publishEvent(Event event) {
                published.set(true);
                return CompletableFuture.completedFuture("event-id");
            }
        };
        carolClient.setEventsToDeliver(aliceEvent, bobEvent);

        try {
            carolClient.publishNametagBinding("contested", carol.getPublicKeyHex()).get();
            fail("Expected exception for contested nametag");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("already claimed") || e.getCause().getMessage().contains("already claimed"));
        }
        assertFalse(published.get());
    }

    @Test
    public void shouldSucceedWhenPublisherIsOneOfTheContestingAuthors() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // Lets a legacy owner republish (e.g. migrate to a marked binding) even
        // when someone else has published a competing legacy binding.
        Event aliceEvent = createSignedBinding(alice, "contested", 1000);
        Event bobEvent = createSignedBinding(bob, "contested", 2000);

        FakeNostrClient client = new FakeNostrClient(alice) {
            @Override
            public CompletableFuture<String> publishEvent(Event event) {
                return CompletableFuture.completedFuture("event-id");
            }
        };
        client.setEventsToDeliver(aliceEvent, bobEvent);

        assertTrue(client.publishNametagBinding("contested", alice.getPublicKeyHex()).get());
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
    public void legacyBindingContestedByBobNeverResolvesToBob() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event aliceEvent = createSignedBinding(alice, "alice", 1000);
        // Unmarked bindings are not relay-vetted, so nothing stops Bob publishing one.
        Event bobEvent = createSignedBinding(bob, "alice", 2000);

        // Nothing the client can see tells the real owner apart, so resolution
        // refuses rather than sending to Bob.
        NostrKeyManager resolver = NostrKeyManager.generate();
        FakeNostrClient resolverClient = new FakeNostrClient(resolver);
        resolverClient.setEventsToDeliver(bobEvent, aliceEvent);

        String resolvedPubkey = resolverClient.queryPubkeyByNametag("alice").get();
        assertNull(resolvedPubkey);
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

    // =========================================================================
    // UNIP-01: marker-preferring resolution (created_at is not authoritative)
    // =========================================================================

    @Test
    public void markedOwnerWinsOverUnmarkedBackdatedBinding() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager attacker = NostrKeyManager.generate();

        Event owner = createMarkedBinding(alice, "alice", 2000);   // UNIP-01 marked
        Event legacy = createSignedBinding(attacker, "alice", 1);  // unmarked, backdated

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(legacy, owner);

        String resolved = client.queryPubkeyByNametag("alice").get();
        // The relay-vetted (marked) owner is selected; the lower created_at is ignored.
        assertEquals(alice.getPublicKeyHex(), resolved);
        assertNotEquals(attacker.getPublicKeyHex(), resolved);
    }

    @Test
    public void twoDistinctMarkedOwnersResolveToNull() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event a = createMarkedBinding(alice, "alice", 2000);
        Event b = createMarkedBinding(bob, "alice", 1); // lower created_at, also marked

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(a, b);

        String resolved = client.queryPubkeyByNametag("alice").get();
        // Must NOT pick the lower created_at; ambiguous -> null.
        assertNull(resolved);
    }

    @Test
    public void twoUnmarkedAuthorsAreAmbiguousNeverDecidedByCreatedAt() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager attacker = NostrKeyManager.generate();

        Event a = createSignedBinding(alice, "alice", 2000);
        Event b = createSignedBinding(attacker, "alice", 1); // unmarked, backdated

        FakeNostrClient client = new FakeNostrClient(alice);
        client.setEventsToDeliver(a, b);

        // The relay enforces nothing for unmarked bindings, so anyone can publish
        // one under the victim's d tag with any created_at. Refuse to guess.
        assertNull(client.queryPubkeyByNametag("alice").get());
    }

    // =========================================================================
    // UNIP-01: only events that bind the queried identifier count
    // =========================================================================

    private static final String ATTACKER_OWN_D = NametagUtils.hashNametag("mallory");
    private static final String VICTIM_CHAIN = "02" + "a".repeat(64);
    private static final String ATTACKER_CHAIN = "02" + "f".repeat(64);

    /**
     * A signed kind-30078 event under the author's OWN d tag that also carries
     * tTags. Anyone can publish this: the relay vets only the d tag (and only
     * when the event is marked), so t tags are free-form.
     */
    private static Event eventCarryingTags(NostrKeyManager km, String dTag, java.util.List<String> tTags,
                                           java.util.Map<String, String> content, long createdAt,
                                           boolean marked) throws Exception {
        Event event = NametagBinding.createBindingEvent(km, "mallory", km.getPublicKeyHex());
        java.util.List<java.util.List<String>> tags = new java.util.ArrayList<>();
        tags.add(java.util.Arrays.asList("d", dTag));
        if (marked) {
            tags.add(java.util.Arrays.asList("L", NametagBinding.UNICITY_NAMETAG_NAMESPACE));
        }
        for (String t : tTags) {
            tags.add(java.util.Arrays.asList("t", t));
        }
        event.setTags(tags);
        event.setContent(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(content));
        event.setCreatedAt(createdAt);
        resignEvent(km, event);
        return event;
    }

    private static java.util.Map<String, String> content(String... kv) {
        java.util.Map<String, String> m = new java.util.LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put(kv[i], kv[i + 1]);
        }
        return m;
    }

    @Test
    public void nametagLookupIgnoresMarkedBindingForAnotherNametagCarryingVictimTag() throws Exception {
        NostrKeyManager victim = NostrKeyManager.generate();
        NostrKeyManager attacker = NostrKeyManager.generate();
        String victimTag = NametagUtils.hashNametag("alice");

        Event owner = createMarkedBinding(victim, "alice", 2000);
        Event rogue = eventCarryingTags(attacker, ATTACKER_OWN_D, java.util.Arrays.asList(ATTACKER_OWN_D, victimTag),
                content("public_key", ATTACKER_CHAIN, "nametag", "alice"), 2000, true);

        FakeNostrClient client = new FakeNostrClient(NostrKeyManager.generate());
        client.setEventsToDeliver(owner, rogue);

        assertEquals(victim.getPublicKeyHex(), client.queryPubkeyByNametag("alice").get());
    }

    @Test
    public void markedBindingForAnotherNametagCannotTakeOverLegacyNametag() throws Exception {
        NostrKeyManager victim = NostrKeyManager.generate();
        NostrKeyManager attacker = NostrKeyManager.generate();
        String victimTag = NametagUtils.hashNametag("alice");

        Event legacy = createSignedBinding(victim, "alice", 2000);
        Event rogue = eventCarryingTags(attacker, ATTACKER_OWN_D, java.util.Arrays.asList(ATTACKER_OWN_D, victimTag),
                content("public_key", ATTACKER_CHAIN, "nametag", "alice"), 2000, true);

        FakeNostrClient client = new FakeNostrClient(NostrKeyManager.generate());
        client.setEventsToDeliver(legacy, rogue);

        NametagBinding.BindingInfo info = client.queryBindingByNametag("alice").get();
        assertNotNull(info);
        assertEquals(victim.getPublicKeyHex(), info.getTransportPubkey());
    }

    @Test
    public void backdatedUnmarkedEventUnderAnotherDTagCannotTakeOverLegacyNametag() throws Exception {
        NostrKeyManager victim = NostrKeyManager.generate();
        NostrKeyManager attacker = NostrKeyManager.generate();

        Event legacy = createSignedBinding(victim, "alice", 2000);
        Event rogue = eventCarryingTags(attacker, "atk-d",
                java.util.Collections.singletonList(NametagUtils.hashNametag("alice")),
                content("public_key", ATTACKER_CHAIN, "nametag", "alice"), 1, false);

        FakeNostrClient client = new FakeNostrClient(NostrKeyManager.generate());
        client.setEventsToDeliver(legacy, rogue);

        assertEquals(victim.getPublicKeyHex(), client.queryPubkeyByNametag("alice").get());
    }

    @Test
    public void publishNametagBindingIsNotBlockedByBindingForAnotherNametag() throws Exception {
        NostrKeyManager victim = NostrKeyManager.generate();
        NostrKeyManager attacker = NostrKeyManager.generate();

        Event rogue = eventCarryingTags(attacker, ATTACKER_OWN_D,
                java.util.Arrays.asList(ATTACKER_OWN_D, NametagUtils.hashNametag("fresh")),
                content("nametag", "fresh"), 2000, true);

        FakeNostrClient client = new FakeNostrClient(victim) {
            @Override
            public CompletableFuture<String> publishEvent(Event event) {
                return CompletableFuture.completedFuture("event-id");
            }
        };
        client.setEventsToDeliver(rogue);

        assertTrue(client.publishNametagBinding("fresh", victim.getPublicKeyHex()).get());
    }

    private static Event victimIdentity(NostrKeyManager victim, String address) throws Exception {
        NametagBinding.IdentityBindingParams params = new NametagBinding.IdentityBindingParams();
        params.setPublicKey(VICTIM_CHAIN);
        params.setDirectAddress(address);
        return NametagBinding.createIdentityBindingEvent(victim, params);
    }

    @Test
    public void addressLookupResolvesTheOnlyAuthor() throws Exception {
        NostrKeyManager victim = NostrKeyManager.generate();
        String address = "DIRECT://victim-address";

        FakeNostrClient client = new FakeNostrClient(NostrKeyManager.generate());
        client.setEventsToDeliver(victimIdentity(victim, address));

        NametagBinding.BindingInfo info = client.queryBindingByAddress(address).get();
        assertNotNull(info);
        assertEquals(victim.getPublicKeyHex(), info.getTransportPubkey());
        assertEquals(VICTIM_CHAIN, info.getPublicKey());
    }

    @Test
    public void addressLookupWithTwoAuthorsIsAmbiguousNeverDecidedByCreatedAt() throws Exception {
        NostrKeyManager victim = NostrKeyManager.generate();
        NostrKeyManager attacker = NostrKeyManager.generate();
        String address = "DIRECT://victim-address";

        Event rogue = eventCarryingTags(attacker, "atk-d",
                java.util.Collections.singletonList(NametagUtils.hashAddressForTag(address)),
                content("public_key", ATTACKER_CHAIN, "direct_address", address), 1, false);

        FakeNostrClient client = new FakeNostrClient(NostrKeyManager.generate());
        client.setEventsToDeliver(victimIdentity(victim, address), rogue);

        assertNull(client.queryBindingByAddress(address).get());
    }

    @Test
    public void addressLookupIgnoresTheOwnershipMarker() throws Exception {
        NostrKeyManager victim = NostrKeyManager.generate();
        NostrKeyManager attacker = NostrKeyManager.generate();
        String address = "DIRECT://victim-address";

        // A marked binding vouches for its own nametag, not for an address.
        Event rogue = eventCarryingTags(attacker, ATTACKER_OWN_D,
                java.util.Arrays.asList(ATTACKER_OWN_D, NametagUtils.hashAddressForTag(address)),
                content("public_key", ATTACKER_CHAIN, "direct_address", address), 2000, true);

        FakeNostrClient client = new FakeNostrClient(NostrKeyManager.generate());
        client.setEventsToDeliver(victimIdentity(victim, address), rogue);

        assertNull(client.queryBindingByAddress(address).get());
    }

    @Test
    public void addressLookupIgnoresRelayInjectedEventsWithoutTheAddressTag() throws Exception {
        NostrKeyManager victim = NostrKeyManager.generate();
        NostrKeyManager attacker = NostrKeyManager.generate();
        String address = "DIRECT://victim-address";

        Event unrelated = eventCarryingTags(attacker, "atk-d",
                java.util.Collections.singletonList(NametagUtils.hashAddressForTag("DIRECT://other")),
                content("public_key", ATTACKER_CHAIN, "direct_address", address), 1, false);

        FakeNostrClient client = new FakeNostrClient(NostrKeyManager.generate());
        client.setEventsToDeliver(victimIdentity(victim, address), unrelated);

        NametagBinding.BindingInfo info = client.queryBindingByAddress(address).get();
        assertNotNull(info);
        assertEquals(victim.getPublicKeyHex(), info.getTransportPubkey());
    }
}

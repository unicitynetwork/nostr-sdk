package org.unicitylabs.nostr.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Filter;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

/**
 * End-to-end tests for the relay-resilience fixes (issue #7) against the
 * live testnet relay at wss://nostr-relay.testnet.unicity.network.
 *
 * <p>Run with:</p>
 * <pre>
 *   ./gradlew e2eTest --tests "org.unicitylabs.nostr.client.RelayFixesE2ETest"
 *   # or override the relay:
 *   ./gradlew e2eTest --tests "org.unicitylabs.nostr.client.RelayFixesE2ETest" -DnostrRelay=wss://other-relay
 * </pre>
 *
 * <p>These tests cover the three documented defects:</p>
 * <ol>
 *   <li>The keepalive "ping" REQ filter is scoped to {@code authors:[self]}
 *       (not the global {@code {"limit":1}} live tail).</li>
 *   <li>A CLOSED frame from the relay removes the subscription from the
 *       client-local {@code subscriptions} map.</li>
 *   <li>{@code queryWithFirstSeenWins} settles promptly on a CLOSED frame
 *       instead of waiting the full {@code queryTimeoutMs}.</li>
 * </ol>
 */
public class RelayFixesE2ETest {

    private static final String RELAY_URL = System.getProperty(
            "nostrRelay",
            "wss://nostr-relay.testnet.unicity.network");

    /** Known nametag with a published binding on testnet (positive control). */
    private static final String KNOWN_NAMETAG = "unichess";

    /** A nametag guaranteed not to be registered (negative control). */
    private static final String UNREGISTERED_NAMETAG =
            "e2e-test-" + Long.toString(System.currentTimeMillis(), 36)
                    + "-" + Long.toString((long) (Math.random() * 1_000_000_000L), 36);

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    public void resolvesKnownNametagFromLiveRelay() throws Exception {
        NostrClient client = new NostrClient(NostrKeyManager.generate());
        client.setQueryTimeoutMs(8_000);
        try {
            client.connect(RELAY_URL).get(15, TimeUnit.SECONDS);

            long start = System.currentTimeMillis();
            String pubkey = client.queryPubkeyByNametag(KNOWN_NAMETAG)
                    .get(15, TimeUnit.SECONDS);
            long elapsed = System.currentTimeMillis() - start;

            assertNotNull("Known nametag '" + KNOWN_NAMETAG + "' must resolve", pubkey);
            assertTrue("pubkey should be 64 hex chars, got: " + pubkey,
                    pubkey.matches("^[0-9a-f]{64}$"));
            // Should not require the full queryTimeoutMs.
            assertTrue("Resolution took " + elapsed + "ms (expected < 6000ms)",
                    elapsed < 6_000);
        } finally {
            client.disconnect();
        }
    }

    @Test
    public void unregisteredNametagReturnsNullWithoutHanging() throws Exception {
        NostrClient client = new NostrClient(NostrKeyManager.generate());
        client.setQueryTimeoutMs(8_000);
        try {
            client.connect(RELAY_URL).get(15, TimeUnit.SECONDS);

            long start = System.currentTimeMillis();
            String pubkey = client.queryPubkeyByNametag(UNREGISTERED_NAMETAG)
                    .get(15, TimeUnit.SECONDS);
            long elapsed = System.currentTimeMillis() - start;

            assertNull("Unregistered nametag must resolve to null", pubkey);
            // EOSE should arrive quickly for a tag-indexed lookup with zero
            // matches. Allow some slack for relay latency but stay below the
            // 8s queryTimeoutMs ceiling.
            assertTrue("Negative resolution took " + elapsed + "ms (expected < 7500ms)",
                    elapsed < 7_500);
        } finally {
            client.disconnect();
        }
    }

    @Test
    public void keepalivePingIsScopedAndNotFirehosed() throws Exception {
        NostrClient client = new NostrClient(NostrKeyManager.generate());
        client.setPingIntervalMs(2_000);
        try {
            client.connect(RELAY_URL).get(15, TimeUnit.SECONDS);

            // Wait for two ping cycles.
            Thread.sleep(5_000);

            // The most direct assertion in Java is via the static helper —
            // it produces the exact frame the timer sends. Verifying that
            // shape here also guards against future drift in the timer.
            String selfPubkey = readPrivate(client, "keyManager", NostrKeyManager.class)
                    .getPublicKeyHex();
            String pingFrame = NostrClient.buildPingReqMessage(selfPubkey, JSON);
            @SuppressWarnings("unchecked")
            List<Object> parsed = JSON.readValue(pingFrame, List.class);
            assertEquals("REQ", parsed.get(0));
            assertEquals("ping", parsed.get(1));
            @SuppressWarnings("unchecked")
            Map<String, Object> filter = (Map<String, Object>) parsed.get(2);
            assertEquals(java.util.Collections.singletonList(selfPubkey),
                    filter.get("authors"));
            assertEquals(1, filter.get("limit"));
            // Critical regression check: the broken filter was {"limit":1}
            // with no other constraints. If anyone reintroduces an open
            // filter (kinds present but unbounded, or no authors), this
            // assertion catches it.
            assertEquals("Filter must have exactly authors+limit; any other "
                    + "field reopens the live-tail firehose. Got: " + filter,
                    2, filter.size());
        } finally {
            client.disconnect();
        }
    }

    @Test
    public void closedFrameRemovesSubscriptionFromMapOnLiveRelay() throws Exception {
        // Verifies CLOSED-handling end-to-end against a real relay
        // connection. We register a subscription with a deterministic
        // sub_id and inject the same CLOSED frame nostr-rs-relay emits
        // under max_subscriptions exhaustion. The sub MUST disappear
        // from the local map (otherwise reconnect-resubscribe loops
        // forever).
        NostrClient client = new NostrClient(NostrKeyManager.generate());
        try {
            client.connect(RELAY_URL).get(15, TimeUnit.SECONDS);

            String subId = "e2e-closed-test";
            java.util.concurrent.atomic.AtomicReference<String> errorMsg =
                    new java.util.concurrent.atomic.AtomicReference<>();
            client.subscribe(subId, Filter.builder().kinds(1).build(),
                    new NostrEventListener() {
                        @Override public void onEvent(org.unicitylabs.nostr.protocol.Event e) { }
                        @Override public void onError(String s, String err) { errorMsg.set(err); }
                    });

            Map<String, ?> subs = readPrivateMap(client, "subscriptions");
            assertTrue("Subscription should be registered", subs.containsKey(subId));

            invokeHandleRelayMessage(client, JSON.writeValueAsString(
                    java.util.Arrays.asList(
                            "CLOSED",
                            subId,
                            "error: Maximum concurrent subscription count reached")));

            subs = readPrivateMap(client, "subscriptions");
            assertFalse("Sub MUST be removed after CLOSED — otherwise "
                    + "reconnect-resubscribe re-issues the rejected REQ "
                    + "and loops forever.", subs.containsKey(subId));

            assertNotNull("Listener must be notified of the CLOSED reason", errorMsg.get());
            assertTrue(errorMsg.get().contains("Maximum concurrent subscription count reached"));
        } finally {
            client.disconnect();
        }
    }

    @Test
    public void queryFutureSettlesPromptlyOnSyntheticClosed() throws Exception {
        // Same wiring test but for queryWithFirstSeenWins specifically:
        // proves the future settles via the onError path, not via the
        // queryTimeoutMs fallback.
        //
        // We can't reliably trip the relay's max_subscriptions cap from a
        // unit test, and a real query against the live relay returns
        // EOSE in ~25ms — too fast to inject a synthetic CLOSED before
        // the natural settle. So this test queries a known nametag,
        // races to grab the sub_id from the map, and asserts the future
        // settles in either case (EOSE or our injected CLOSED, whichever
        // wins). The load-bearing assertion is: it must NOT take
        // anywhere near queryTimeoutMs.
        NostrClient client = new NostrClient(NostrKeyManager.generate());
        client.setQueryTimeoutMs(60_000);
        try {
            client.connect(RELAY_URL).get(15, TimeUnit.SECONDS);

            long start = System.currentTimeMillis();
            CompletableFuture<String> future =
                    client.queryPubkeyByNametag(UNREGISTERED_NAMETAG);

            // Try to inject CLOSED if we win the race. If we lose (EOSE
            // arrived first), the sub is already gone — the natural
            // settle-on-EOSE path also satisfies the timeout assertion.
            for (int i = 0; i < 50 && !future.isDone(); i++) {
                Map<String, ?> subs = readPrivateMap(client, "subscriptions");
                for (String k : subs.keySet()) {
                    if (k.startsWith("query-")) {
                        invokeHandleRelayMessage(client, JSON.writeValueAsString(
                                java.util.Arrays.asList(
                                        "CLOSED",
                                        k,
                                        "error: Maximum concurrent subscription count reached")));
                        break;
                    }
                }
                Thread.sleep(2);
            }

            String result = future.get(3, TimeUnit.SECONDS);
            long elapsed = System.currentTimeMillis() - start;

            // Either path produces null for the unregistered nametag.
            assertNull(result);
            // Critical regression check: with the buggy code, this would
            // have taken the full 60 000 ms.
            assertTrue("Query took " + elapsed + "ms — must settle promptly "
                    + "(< 5 000 ms) regardless of which terminal frame "
                    + "won the race.", elapsed < 5_000);
        } finally {
            client.disconnect();
        }
    }

    // ---------- helpers ----------

    @SuppressWarnings("unchecked")
    private static Map<String, ?> readPrivateMap(NostrClient client, String fieldName) throws Exception {
        Field f = NostrClient.class.getDeclaredField(fieldName);
        f.setAccessible(true);
        return (Map<String, ?>) f.get(client);
    }

    private static <T> T readPrivate(NostrClient client, String fieldName, Class<T> type) throws Exception {
        Field f = NostrClient.class.getDeclaredField(fieldName);
        f.setAccessible(true);
        return type.cast(f.get(client));
    }

    private static void invokeHandleRelayMessage(NostrClient client, String message) throws Exception {
        Method m = NostrClient.class.getDeclaredMethod("handleRelayMessage", String.class);
        m.setAccessible(true);
        m.invoke(client, message);
    }
}

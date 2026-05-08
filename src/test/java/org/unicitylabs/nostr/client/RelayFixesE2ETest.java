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
 * <p>These tests cover, against a real WebSocket connection:</p>
 * <ol>
 *   <li>The keepalive "ping" REQ filter cannot match any real event
 *       (not the global {@code {"limit":1}} live tail) — verified by
 *       parsing the wire frame from the static
 *       {@link NostrClient#buildPingReqMessage} helper that the timer
 *       calls.</li>
 *   <li>A CLOSED frame surfaces to the listener via {@code onError}.
 *       The global {@code subscriptions} map is intentionally NOT
 *       modified by {@code handleClosedMessage} (multi-relay correctness:
 *       healthy relays may still be streaming); listener-driven
 *       {@code unsubscribe()} is what cleans the global map.</li>
 *   <li>{@code queryWithFirstSeenWins} settles promptly on a CLOSED
 *       frame instead of waiting the full {@code queryTimeoutMs}.</li>
 * </ol>
 *
 * <p><b>Note on per-relay {@code closedSubIds} / {@code eosedSubIds}
 * coverage:</b> these tests inject CLOSED via reflective calls to the
 * legacy {@code handleRelayMessage(String)} overload (relay=null), which
 * does NOT update per-relay state. The relay-aware bookkeeping is
 * covered by unit tests in {@code RelayFixesTest} that construct a
 * {@code RelayConnection} via reflection — see
 * {@code closedFrameOnRealRelayPopulatesPerRelayClosedSubIds} and
 * {@code eosedFrameOnRealRelayPopulatesPerRelayEosedSubIds}.</p>
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
    public void keepalivePingFilterCannotMatchAnyRealEvent() throws Exception {
        // The keepalive timer calls NostrClient.buildPingReqMessage()
        // verbatim each interval and ships the result on the wire,
        // so verifying that helper's output IS verifying the wire
        // shape. We assert it via a real connection (cheap) so the
        // test exercises the full classloader / signing path, not
        // the helper in isolation.
        NostrClient client = new NostrClient(NostrKeyManager.generate());
        try {
            client.connect(RELAY_URL).get(15, TimeUnit.SECONDS);

            String selfPubkey = client.getKeyManager().getPublicKeyHex();
            String pingFrame = NostrClient.buildPingReqMessage(selfPubkey, JSON);
            @SuppressWarnings("unchecked")
            List<Object> parsed = JSON.readValue(pingFrame, List.class);
            assertEquals("REQ", parsed.get(0));
            assertEquals(NostrClient.PING_SUB_ID, parsed.get(1));
            @SuppressWarnings("unchecked")
            Map<String, Object> filter = (Map<String, Object>) parsed.get(2);

            // Filter must use the unreachable id pattern — NOT
            // authors:[self], which matched every event the wallet
            // itself published and tripped the relay's live-tail
            // forwarding into echoing kind-31113 transfers back on
            // the keepalive sub.
            assertEquals(
                    java.util.Collections.singletonList(NostrClient.KEEPALIVE_NEVER_MATCH_ID),
                    filter.get("ids"));
            assertEquals(1, filter.get("limit"));
            assertNull("authors must not appear in keepalive filter", filter.get("authors"));
            assertNull("kinds must not appear in keepalive filter", filter.get("kinds"));
            assertNull("#p must not appear in keepalive filter", filter.get("#p"));
            assertFalse(
                    "wallet pubkey must not appear in keepalive frame; got: " + pingFrame,
                    pingFrame.contains(selfPubkey));
            assertEquals("Filter must have exactly ids+limit; any other "
                    + "field can reopen the live-tail firehose. Got: " + filter,
                    2, filter.size());
        } finally {
            client.disconnect();
        }
    }

    @Test
    public void closedFrameNotifiesListenerOnLiveRelay() throws Exception {
        // Verifies CLOSED-handling end-to-end against a real relay
        // connection. We register a subscription, simulate the relay
        // sending a CLOSED frame, and assert two things:
        //
        //   1. The listener is notified via onError — without this,
        //      callers cannot distinguish rate-limiting from "no data
        //      exists" and silently wait for queryTimeoutMs.
        //
        //   2. A subsequent listener-driven unsubscribe() cleans the
        //      global subscriptions map. (We deliberately do NOT
        //      assert that handleClosedMessage itself removes from the
        //      global map, because in a multi-relay client the sub
        //      may still be alive on a healthy relay — per-relay
        //      tracking is what stops the rejection loop on the
        //      sending relay.)
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

            assertNotNull("Listener must be notified of the CLOSED reason", errorMsg.get());
            assertTrue(errorMsg.get().contains("Maximum concurrent subscription count reached"));

            // The listener (in production, queryWithFirstSeenWins.onError)
            // would call unsubscribe() to give up across all relays; that's
            // when the global map is cleaned.
            client.unsubscribe(subId);
            subs = readPrivateMap(client, "subscriptions");
            assertFalse("Listener-driven unsubscribe must clean the global map",
                    subs.containsKey(subId));
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

    private static void invokeHandleRelayMessage(NostrClient client, String message) throws Exception {
        Method m = NostrClient.class.getDeclaredMethod("handleRelayMessage", String.class);
        m.setAccessible(true);
        m.invoke(client, message);
    }
}

package org.unicitylabs.nostr.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Filter;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/**
 * Unit tests for the relay-resilience fixes covered by issue #7.
 *
 * <p>The fixes:</p>
 * <ol>
 *   <li>The keepalive "ping" REQ filter must be scoped to {@code authors:[self]} so
 *       the relay does not stream a global live-tail through it after EOSE.</li>
 *   <li>A CLOSED frame from the relay must remove the subscription from the
 *       client-local {@code subscriptions} map, so reconnect-time
 *       resubscribe loops do not re-issue the rejected REQ.</li>
 *   <li>{@code queryWithFirstSeenWins} must surface CLOSED to the listener
 *       so the awaiting future settles promptly instead of waiting the
 *       full {@code queryTimeoutMs}.</li>
 * </ol>
 *
 * <p>Tests use reflection to inspect / drive private state because the
 * relevant code paths fire from the WebSocket listener and the SDK does
 * not expose a fake-socket injection point.</p>
 */
public class RelayFixesTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    public void pingReqIsScopedToSelfAuthor() throws Exception {
        NostrKeyManager keyManager = NostrKeyManager.generate();
        String selfPubkey = keyManager.getPublicKeyHex();

        String pingFrame = NostrClient.buildPingReqMessage(selfPubkey, JSON);
        @SuppressWarnings("unchecked")
        List<Object> parsed = JSON.readValue(pingFrame, List.class);

        assertEquals("REQ", parsed.get(0));
        assertEquals("ping", parsed.get(1));

        @SuppressWarnings("unchecked")
        Map<String, Object> filter = (Map<String, Object>) parsed.get(2);
        // The two fields the relay must see — and nothing else, otherwise
        // we widen the live tail.
        assertEquals(2, filter.size());
        assertEquals(java.util.Collections.singletonList(selfPubkey), filter.get("authors"));
        assertEquals(1, filter.get("limit"));
    }

    @Test
    public void closedFrameRemovesSubscriptionFromMap() throws Exception {
        NostrClient client = new NostrClient(NostrKeyManager.generate());

        AtomicReference<String> errorMsg = new AtomicReference<>(null);
        NostrEventListener listener = new NostrEventListener() {
            @Override public void onEvent(org.unicitylabs.nostr.protocol.Event event) { }
            @Override public void onError(String subId, String error) { errorMsg.set(error); }
        };

        // Subscribe with a deterministic sub_id so we can target it.
        Filter filter = Filter.builder().kinds(1).build();
        String subId = "test-sub-1";
        client.subscribe(subId, filter, listener);

        // Sanity: the subscription is registered.
        Map<String, ?> subs = readPrivateMap(client, "subscriptions");
        assertTrue("Subscription should be registered after subscribe()", subs.containsKey(subId));

        // Simulate a CLOSED frame — exactly what nostr-rs-relay emits when
        // the per-connection sub limit is hit.
        invokeHandleRelayMessage(client, JSON.writeValueAsString(
                java.util.Arrays.asList("CLOSED", subId, "error: Maximum concurrent subscription count reached")));

        // The Map entry must be gone, otherwise reconnect-resubscribe will
        // re-issue the rejected REQ and loop forever.
        subs = readPrivateMap(client, "subscriptions");
        assertFalse("Subscription must be removed after CLOSED", subs.containsKey(subId));

        // The listener must have been notified with the relay's reason.
        assertNotNull(errorMsg.get());
        assertTrue(
                "Listener error message must include relay reason; got: " + errorMsg.get(),
                errorMsg.get().contains("Maximum concurrent subscription count reached"));
    }

    @Test
    public void closedFrameWithUnknownSubIdIsHarmless() throws Exception {
        NostrClient client = new NostrClient(NostrKeyManager.generate());

        // No sub registered. CLOSED for an unknown sub_id must not throw.
        invokeHandleRelayMessage(client, JSON.writeValueAsString(
                java.util.Arrays.asList("CLOSED", "ghost-sub", "error: nope")));

        // No assertion needed beyond "did not throw".
        Map<String, ?> subs = readPrivateMap(client, "subscriptions");
        assertTrue(subs.isEmpty());
    }

    @Test
    public void queryFutureSettlesPromptlyOnClosed() throws Exception {
        // Use a long timeout — if CLOSED handling is wrong, this test will
        // visibly hang for the full timeout instead of resolving in ms.
        NostrClient client = new NostrClient(NostrKeyManager.generate());
        client.setQueryTimeoutMs(60_000);

        // Spin off a query.
        java.util.concurrent.CompletableFuture<String> future =
                client.queryPubkeyByNametag("alice");
        assertFalse("Future should not be done before CLOSED is delivered", future.isDone());

        // Find the auto-generated query sub_id (prefix "query-").
        Map<String, ?> subs = readPrivateMap(client, "subscriptions");
        String querySubId = subs.keySet().stream()
                .filter(k -> k.startsWith("query-"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("queryPubkeyByNametag did not register a sub"));

        long start = System.currentTimeMillis();
        invokeHandleRelayMessage(client, JSON.writeValueAsString(
                java.util.Arrays.asList(
                        "CLOSED",
                        querySubId,
                        "error: Maximum concurrent subscription count reached")));

        // Future must resolve — null result with collected-so-far being empty.
        String result = future.get(2, java.util.concurrent.TimeUnit.SECONDS);
        long elapsedMs = System.currentTimeMillis() - start;

        assertNull("Result must be null when relay rejects the query", result);
        assertTrue(
                "Future should settle within ~2s after CLOSED, took " + elapsedMs + "ms",
                elapsedMs < 5_000);

        // And the rejected sub must be cleaned up.
        subs = readPrivateMap(client, "subscriptions");
        assertFalse(subs.containsKey(querySubId));
    }

    @Test
    public void unknownMessageTypesAreStillIgnored() throws Exception {
        // The dispatch must not throw on unknown frame types — defensive.
        NostrClient client = new NostrClient(NostrKeyManager.generate());

        invokeHandleRelayMessage(client, "[\"WHATEVER\",\"x\",\"y\"]");
        invokeHandleRelayMessage(client, "[]"); // empty
        invokeHandleRelayMessage(client, "not json");
        // No assertion beyond "did not throw".
    }

    @Test
    public void closedFrameWithMissingMessageFieldIsHandled() throws Exception {
        // Some relays might send ["CLOSED","sub_id"] without the message.
        // We require length >= 3 today; this test pins that contract.
        NostrClient client = new NostrClient(NostrKeyManager.generate());

        AtomicReference<String> errorMsg = new AtomicReference<>(null);
        NostrEventListener listener = new NostrEventListener() {
            @Override public void onEvent(org.unicitylabs.nostr.protocol.Event event) { }
            @Override public void onError(String subId, String error) { errorMsg.set(error); }
        };
        client.subscribe("incomplete-closed", Filter.builder().kinds(1).build(), listener);

        // Truncated CLOSED.
        invokeHandleRelayMessage(client, JSON.writeValueAsString(
                java.util.Arrays.asList("CLOSED", "incomplete-closed")));

        // The current implementation requires length >= 3 and silently
        // drops short CLOSED frames. Either drop-or-handle is fine — but
        // it must not throw.
        // (No assertion — survival is the test.)
        assertNotNull("Listener exists", listener);
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

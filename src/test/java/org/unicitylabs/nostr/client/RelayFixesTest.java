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
 *   <li>A CLOSED frame from the relay must be surfaced to the listener via
 *       {@code onError} (and recorded per-relay so reconnect resubscribe
 *       skips it), without removing the subscription from the global map —
 *       healthy relays in a multi-relay client may still be streaming.</li>
 *   <li>{@code queryWithFirstSeenWins} must surface CLOSED to the listener
 *       so the awaiting future settles promptly instead of waiting the
 *       full {@code queryTimeoutMs}.</li>
 * </ol>
 *
 * <p>Tests use reflection to drive private dispatch because the relevant
 * code paths fire from the WebSocket listener and the SDK does not expose
 * a fake-socket injection point. Two reflection paths are used:</p>
 * <ul>
 *   <li><b>Legacy path</b> — {@code handleRelayMessage(String)} with
 *       {@code relay = null}. Exercises listener notification, the global
 *       {@code subscriptions} map, and the static
 *       {@link NostrClient#isTransientCloseReason} decision logic, but
 *       does NOT populate per-relay {@code closedSubIds} /
 *       {@code eosedSubIds}.</li>
 *   <li><b>Relay-aware path</b> — construct a {@code RelayConnection}
 *       inner-class instance via reflection, mark it connected, then
 *       invoke {@code handleRelayMessage(RelayConnection, String)}.
 *       Exercises the per-relay bookkeeping that production code drives
 *       from the OkHttp WebSocket listener. See
 *       {@link #closedFrameOnRealRelayPopulatesPerRelayClosedSubIds}.</li>
 * </ul>
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
    public void closedFrameNotifiesListenerWithRelayReason() throws Exception {
        NostrClient client = new NostrClient(NostrKeyManager.generate());

        AtomicReference<String> errorMsg = new AtomicReference<>(null);
        NostrEventListener listener = new NostrEventListener() {
            @Override public void onEvent(org.unicitylabs.nostr.protocol.Event event) { }
            @Override public void onError(String subId, String error) { errorMsg.set(error); }
        };

        Filter filter = Filter.builder().kinds(1).build();
        String subId = "test-sub-1";
        client.subscribe(subId, filter, listener);

        invokeHandleRelayMessage(client, JSON.writeValueAsString(
                java.util.Arrays.asList("CLOSED", subId, "error: Maximum concurrent subscription count reached")));

        // The listener is notified with the relay's reason. The global
        // Map is intentionally NOT modified here — multi-relay clients
        // may still have the same sub alive on a healthy relay; per-relay
        // tracking via the RelayConnection.closedSubIds set is what
        // prevents the rejection loop on the *sending* relay specifically.
        assertNotNull(errorMsg.get());
        assertTrue(
                "Listener error message must include relay reason; got: " + errorMsg.get(),
                errorMsg.get().contains("Maximum concurrent subscription count reached"));
    }

    @Test
    public void closedFrameWithMissingMessageFieldIsHandled() throws Exception {
        // NIP-01 makes the message field optional. The handler must
        // notify the listener with a default reason, not silently drop
        // the frame (the latter would leak the sub on the relay's
        // per-connection slot count just like the unfixed bug).
        NostrClient client = new NostrClient(NostrKeyManager.generate());

        AtomicReference<String> errorMsg = new AtomicReference<>(null);
        NostrEventListener listener = new NostrEventListener() {
            @Override public void onEvent(org.unicitylabs.nostr.protocol.Event event) { }
            @Override public void onError(String subId, String error) { errorMsg.set(error); }
        };
        client.subscribe("incomplete-closed", Filter.builder().kinds(1).build(), listener);

        invokeHandleRelayMessage(client, JSON.writeValueAsString(
                java.util.Arrays.asList("CLOSED", "incomplete-closed")));

        assertNotNull("Listener must be notified even when message field is missing",
                errorMsg.get());
        assertTrue(
                "Default reason should be present; got: " + errorMsg.get(),
                errorMsg.get().toLowerCase().contains("no reason"));
    }

    @Test
    public void closedFrameWithUnknownSubIdIsHarmless() throws Exception {
        NostrClient client = new NostrClient(NostrKeyManager.generate());

        invokeHandleRelayMessage(client, JSON.writeValueAsString(
                java.util.Arrays.asList("CLOSED", "ghost-sub", "error: nope")));

        Map<String, ?> subs = readPrivateMap(client, "subscriptions");
        assertTrue(subs.isEmpty());
    }

    @Test
    public void closedFrameForUnknownSubIdDoesNotNotifyListener_dosGuard() throws Exception {
        // A misbehaving or malicious relay can spam CLOSED frames for
        // arbitrary sub_ids the client never subscribed to. We must
        // NOT pass those through to listeners — and on the relay path
        // (covered by e2e) we must not record them in closedSubIds
        // either, since the set would otherwise grow unbounded.
        NostrClient client = new NostrClient(NostrKeyManager.generate());

        AtomicReference<String> errorMsg = new AtomicReference<>();
        NostrEventListener listener = new NostrEventListener() {
            @Override public void onEvent(org.unicitylabs.nostr.protocol.Event e) { }
            @Override public void onError(String subId, String error) { errorMsg.set(error); }
        };
        // Register a real listener on a known sub so we can prove this
        // path doesn't accidentally fire it.
        client.subscribe("real-sub", Filter.builder().kinds(1).build(), listener);

        invokeHandleRelayMessage(client, JSON.writeValueAsString(
                java.util.Arrays.asList("CLOSED", "ghost-sub", "rejected")));

        assertNull("Listener for a different sub must NOT be notified for ghost CLOSED",
                errorMsg.get());
    }

    @Test
    public void closedFrameOnRealRelayPopulatesPerRelayClosedSubIds() throws Exception {
        // Copilot: the existing tests drive the legacy
        // handleRelayMessage(String) path with relay=null, which
        // does NOT populate per-relay closedSubIds. Cover that
        // specific bookkeeping by constructing a real RelayConnection
        // via reflection and invoking the relay-aware dispatcher.
        NostrClient client = new NostrClient(NostrKeyManager.generate());

        // Construct a RelayConnection (non-static inner class — pass
        // the outer NostrClient instance to its constructor).
        Class<?> rcClass = Class.forName("org.unicitylabs.nostr.client.NostrClient$RelayConnection");
        java.lang.reflect.Constructor<?> ctor = rcClass.getDeclaredConstructor(
                NostrClient.class, String.class, java.util.concurrent.CompletableFuture.class);
        ctor.setAccessible(true);
        Object relay = ctor.newInstance(client, "ws://test", new java.util.concurrent.CompletableFuture<>());

        // Mark the relay connected (simulates post-onOpen state).
        java.lang.reflect.Field connectedField = rcClass.getDeclaredField("connected");
        connectedField.setAccessible(true);
        connectedField.setBoolean(relay, true);

        // Register a sub.
        Filter filter = Filter.builder().kinds(1).build();
        client.subscribe("real-path-sub", filter, new NostrEventListener() {
            @Override public void onEvent(org.unicitylabs.nostr.protocol.Event e) { }
        });

        // Drive the relay-aware dispatcher directly.
        java.lang.reflect.Method dispatch = NostrClient.class.getDeclaredMethod(
                "handleRelayMessage", rcClass, String.class);
        dispatch.setAccessible(true);

        // Terminal CLOSED reason → MUST land in this relay's closedSubIds.
        dispatch.invoke(client, relay, JSON.writeValueAsString(
                java.util.Arrays.asList("CLOSED", "real-path-sub", "rate-limited: too many")));

        java.lang.reflect.Field closedSubIdsField = rcClass.getDeclaredField("closedSubIds");
        closedSubIdsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.Set<String> closed = (java.util.Set<String>) closedSubIdsField.get(relay);
        assertTrue("Terminal CLOSED must populate this relay's closedSubIds",
                closed.contains("real-path-sub"));

        // Auth-required CLOSED on a different sub → MUST NOT land
        // in closedSubIds (NIP-42 transient).
        client.subscribe("auth-sub", filter, new NostrEventListener() {
            @Override public void onEvent(org.unicitylabs.nostr.protocol.Event e) { }
        });
        dispatch.invoke(client, relay, JSON.writeValueAsString(
                java.util.Arrays.asList("CLOSED", "auth-sub", "auth-required: please")));
        assertFalse("auth-required CLOSED must NOT populate closedSubIds (transient)",
                closed.contains("auth-sub"));
    }

    @Test
    public void eosedFrameOnRealRelayPopulatesPerRelayEosedSubIds() throws Exception {
        // Sibling of the closedSubIds test: verify EOSE bookkeeping
        // through the relay-aware path.
        NostrClient client = new NostrClient(NostrKeyManager.generate());

        Class<?> rcClass = Class.forName("org.unicitylabs.nostr.client.NostrClient$RelayConnection");
        java.lang.reflect.Constructor<?> ctor = rcClass.getDeclaredConstructor(
                NostrClient.class, String.class, java.util.concurrent.CompletableFuture.class);
        ctor.setAccessible(true);
        Object relay = ctor.newInstance(client, "ws://test", new java.util.concurrent.CompletableFuture<>());

        java.lang.reflect.Field connectedField = rcClass.getDeclaredField("connected");
        connectedField.setAccessible(true);
        connectedField.setBoolean(relay, true);

        client.subscribe("eose-sub", Filter.builder().kinds(1).build(), new NostrEventListener() {
            @Override public void onEvent(org.unicitylabs.nostr.protocol.Event e) { }
        });

        java.lang.reflect.Method dispatch = NostrClient.class.getDeclaredMethod(
                "handleRelayMessage", rcClass, String.class);
        dispatch.setAccessible(true);

        dispatch.invoke(client, relay, JSON.writeValueAsString(
                java.util.Arrays.asList("EOSE", "eose-sub")));

        java.lang.reflect.Field eosedField = rcClass.getDeclaredField("eosedSubIds");
        eosedField.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.Set<String> eosed = (java.util.Set<String>) eosedField.get(relay);
        assertTrue("EOSE must populate this relay's eosedSubIds",
                eosed.contains("eose-sub"));
    }

    @Test
    public void isTransientCloseReason_matchesAuthRequiredVariants() {
        // NIP-42: an auth-required CLOSED is transient — the relay
        // will let us retry after we sign the AUTH challenge. We
        // must NOT add such a sub to closedSubIds, otherwise the
        // in-flight query would settle on the first CLOSED, evict
        // the sub from the global Map via unsubscribe(), and lose
        // the post-AUTH retry. The decision is gated entirely on
        // this helper, so testing it directly is sufficient — the
        // production wiring is exercised by the e2e tests against
        // a real connection.
        assertTrue(NostrClient.isTransientCloseReason("auth-required: please authenticate"));
        assertTrue(NostrClient.isTransientCloseReason("auth-required: foo"));
        assertTrue(NostrClient.isTransientCloseReason("auth-required missing tag"));

        // Other reasons are terminal — closedSubIds gets populated
        // and resubscribeAll skips them on this relay.
        assertFalse(NostrClient.isTransientCloseReason("rate-limited: too many concurrent REQs"));
        assertFalse(NostrClient.isTransientCloseReason("blocked: spam"));
        assertFalse(NostrClient.isTransientCloseReason("error: Maximum concurrent subscription count reached"));
        assertFalse(NostrClient.isTransientCloseReason("invalid: bad filter"));
        assertFalse(NostrClient.isTransientCloseReason(""));
        assertFalse(NostrClient.isTransientCloseReason(null));
        // Substring matches in the middle don't count — the prefix
        // must be at the start.
        assertFalse(NostrClient.isTransientCloseReason("rejected: auth-required somewhere"));
    }

    @Test
    public void disconnectSettlesInflightQueriesImmediately() throws Exception {
        // Self-audit invariant: calling disconnect() while a query is
        // in-flight must notify its listener so the future settles
        // promptly, not after the full queryTimeoutMs.
        NostrClient client = new NostrClient(NostrKeyManager.generate());
        client.setQueryTimeoutMs(60_000);

        java.util.concurrent.CompletableFuture<String> future =
                client.queryPubkeyByNametag("alice");
        assertFalse("Query future should be pending before disconnect",
                future.isDone());

        long start = System.currentTimeMillis();
        client.disconnect();
        // Without the fix, the future would hang for the full 60s
        // queryTimeoutMs. With the fix, listener.onError fires
        // synchronously inside disconnect → future settles now.
        String result = future.get(2, java.util.concurrent.TimeUnit.SECONDS);
        long elapsed = System.currentTimeMillis() - start;

        assertNull("Result must be null when disconnected mid-query", result);
        assertTrue("Future settled in " + elapsed + "ms (expected < 1000ms)",
                elapsed < 1_000);
    }

    @Test
    public void eventFrameWithNonStringSubIdIsIgnored() throws Exception {
        // Defensive: parity with the CLOSED/EOSE non-string guards.
        // A relay sending ["EVENT", 42, ...] must not throw or
        // notify any listener.
        NostrClient client = new NostrClient(NostrKeyManager.generate());

        AtomicReference<org.unicitylabs.nostr.protocol.Event> received =
                new AtomicReference<>();
        NostrEventListener listener = new NostrEventListener() {
            @Override public void onEvent(org.unicitylabs.nostr.protocol.Event e) { received.set(e); }
        };
        client.subscribe("real-sub", Filter.builder().kinds(1).build(), listener);

        // Numeric sub_id — must NOT throw, must NOT fire listener.
        invokeHandleRelayMessage(client, "[\"EVENT\", 42, {\"id\":\"x\"}]");
        // Object sub_id.
        invokeHandleRelayMessage(client, "[\"EVENT\", {\"x\":1}, {\"id\":\"y\"}]");

        assertNull("Listener for a different sub must NOT receive a malformed EVENT",
                received.get());
    }

    @Test
    public void closedFrameWithNonStringSubIdIsIgnored() throws Exception {
        NostrClient client = new NostrClient(NostrKeyManager.generate());
        // Numeric sub_id — defensive: don't throw, don't notify.
        invokeHandleRelayMessage(client, "[\"CLOSED\", 42, \"whatever\"]");
        // Object sub_id.
        invokeHandleRelayMessage(client, "[\"CLOSED\", {\"x\":1}, \"whatever\"]");
        // Survival is the test.
    }

    @Test
    public void queryFutureSettlesPromptlyOnClosed() throws Exception {
        // Use a long timeout — if CLOSED handling is wrong, this test will
        // visibly hang for the full timeout instead of resolving in ms.
        NostrClient client = new NostrClient(NostrKeyManager.generate());
        client.setQueryTimeoutMs(60_000);

        java.util.concurrent.CompletableFuture<String> future =
                client.queryPubkeyByNametag("alice");
        assertFalse("Future should not be done before CLOSED is delivered", future.isDone());

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

        // The listener-driven unsubscribe (queryWithFirstSeenWins.onError ->
        // unsubscribe) cleans the sub from the global map.
        subs = readPrivateMap(client, "subscriptions");
        assertFalse(subs.containsKey(querySubId));
    }

    @Test
    public void unknownMessageTypesAreStillIgnored() throws Exception {
        NostrClient client = new NostrClient(NostrKeyManager.generate());

        invokeHandleRelayMessage(client, "[\"WHATEVER\",\"x\",\"y\"]");
        invokeHandleRelayMessage(client, "[]"); // empty
        invokeHandleRelayMessage(client, "not json");
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

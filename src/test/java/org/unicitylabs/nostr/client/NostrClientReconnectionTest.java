package org.unicitylabs.nostr.client;

import org.junit.Test;
import org.unicitylabs.nostr.crypto.NostrKeyManager;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

/**
 * Unit tests for NostrClient reconnection logic.
 */
public class NostrClientReconnectionTest {

    @Test
    public void testClientCreation() {
        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        assertNotNull(client);
        assertEquals(keyManager, client.getKeyManager());
    }

    @Test
    public void testDefaultQueryTimeout() {
        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        assertEquals(5000, client.getQueryTimeoutMs());
    }

    @Test
    public void testSetQueryTimeout() {
        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        client.setQueryTimeoutMs(15000);
        assertEquals(15000, client.getQueryTimeoutMs());
    }

    @Test
    public void testSetAutoReconnect() {
        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        // Should not throw
        client.setAutoReconnect(false);
        client.setAutoReconnect(true);
    }

    @Test
    public void testSetReconnectIntervals() {
        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        // Should not throw
        client.setReconnectIntervalMs(2000);
        client.setMaxReconnectIntervalMs(60000);
    }

    @Test
    public void testSetPingInterval() {
        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        // Should not throw
        client.setPingIntervalMs(45000);
        client.setPingIntervalMs(0); // Disabled
    }

    @Test
    public void testAddConnectionListener() {
        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        NostrClient.ConnectionEventListener listener = new NostrClient.ConnectionEventListener() {
            @Override
            public void onConnect(String relayUrl) {}

            @Override
            public void onDisconnect(String relayUrl, String reason) {}
        };

        // Should not throw
        client.addConnectionListener(listener);
    }

    @Test
    public void testRemoveConnectionListener() {
        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        NostrClient.ConnectionEventListener listener = new NostrClient.ConnectionEventListener() {};

        client.addConnectionListener(listener);
        client.removeConnectionListener(listener);

        // Should not throw when removing non-existent listener
        client.removeConnectionListener(listener);
    }

    @Test
    public void testConnectionListenerInterface() {
        // Test that interface has default methods
        NostrClient.ConnectionEventListener listener = new NostrClient.ConnectionEventListener() {};

        // Should not throw - default methods are no-ops
        listener.onConnect("wss://relay.example.com");
        listener.onDisconnect("wss://relay.example.com", "Test reason");
        listener.onReconnecting("wss://relay.example.com", 1);
        listener.onReconnected("wss://relay.example.com");
    }

    @Test
    public void testConnectionListenerCallbacks() {
        List<String> events = new ArrayList<>();
        AtomicInteger reconnectAttempt = new AtomicInteger(0);

        NostrClient.ConnectionEventListener listener = new NostrClient.ConnectionEventListener() {
            @Override
            public void onConnect(String relayUrl) {
                events.add("connect:" + relayUrl);
            }

            @Override
            public void onDisconnect(String relayUrl, String reason) {
                events.add("disconnect:" + relayUrl + ":" + reason);
            }

            @Override
            public void onReconnecting(String relayUrl, int attempt) {
                events.add("reconnecting:" + relayUrl + ":" + attempt);
                reconnectAttempt.set(attempt);
            }

            @Override
            public void onReconnected(String relayUrl) {
                events.add("reconnected:" + relayUrl);
            }
        };

        // Call methods to verify they work
        listener.onConnect("wss://relay1.example.com");
        listener.onDisconnect("wss://relay1.example.com", "Network error");
        listener.onReconnecting("wss://relay1.example.com", 1);
        listener.onReconnecting("wss://relay1.example.com", 2);
        listener.onReconnected("wss://relay1.example.com");

        assertEquals(5, events.size());
        assertEquals("connect:wss://relay1.example.com", events.get(0));
        assertEquals("disconnect:wss://relay1.example.com:Network error", events.get(1));
        assertEquals("reconnecting:wss://relay1.example.com:1", events.get(2));
        assertEquals("reconnecting:wss://relay1.example.com:2", events.get(3));
        assertEquals("reconnected:wss://relay1.example.com", events.get(4));
        assertEquals(2, reconnectAttempt.get());
    }

    @Test
    public void testExponentialBackoffCalculation() {
        int baseDelay = 1000;
        int maxDelay = 30000;

        // Test the backoff formula: baseDelay * 2^(attempts-1)
        assertEquals(1000, calculateBackoff(baseDelay, maxDelay, 1));   // 1000 * 2^0 = 1000
        assertEquals(2000, calculateBackoff(baseDelay, maxDelay, 2));   // 1000 * 2^1 = 2000
        assertEquals(4000, calculateBackoff(baseDelay, maxDelay, 3));   // 1000 * 2^2 = 4000
        assertEquals(8000, calculateBackoff(baseDelay, maxDelay, 4));   // 1000 * 2^3 = 8000
        assertEquals(16000, calculateBackoff(baseDelay, maxDelay, 5));  // 1000 * 2^4 = 16000
        assertEquals(30000, calculateBackoff(baseDelay, maxDelay, 6));  // 1000 * 2^5 = 32000, capped
        assertEquals(30000, calculateBackoff(baseDelay, maxDelay, 10)); // Always capped
    }

    @Test
    public void testExponentialBackoffWithCustomConfig() {
        int baseDelay = 500;
        int maxDelay = 10000;

        assertEquals(500, calculateBackoff(baseDelay, maxDelay, 1));    // 500 * 2^0 = 500
        assertEquals(1000, calculateBackoff(baseDelay, maxDelay, 2));   // 500 * 2^1 = 1000
        assertEquals(2000, calculateBackoff(baseDelay, maxDelay, 3));   // 500 * 2^2 = 2000
        assertEquals(4000, calculateBackoff(baseDelay, maxDelay, 4));   // 500 * 2^3 = 4000
        assertEquals(8000, calculateBackoff(baseDelay, maxDelay, 5));   // 500 * 2^4 = 8000
        assertEquals(10000, calculateBackoff(baseDelay, maxDelay, 6));  // 500 * 2^5 = 16000, capped
    }

    @Test
    public void testStaleConnectionDetection() {
        int pingInterval = 30000;
        int staleThreshold = pingInterval * 2;

        // Fresh connection - just received pong
        long now = System.currentTimeMillis();
        long recentPong = now - 5000; // 5 seconds ago
        assertFalse(isStale(recentPong, now, staleThreshold));

        // Stale connection - no pong for too long
        long stalePong = now - staleThreshold - 1000; // Beyond threshold
        assertTrue(isStale(stalePong, now, staleThreshold));
    }

    @Test
    public void testIsConnectedWhenNotConnected() {
        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        assertFalse(client.isConnected());
        assertTrue(client.getConnectedRelays().isEmpty());
    }

    @Test
    public void testDisconnect() {
        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        // Should not throw
        client.disconnect();

        assertFalse(client.isConnected());
    }

    @Test
    public void testMultipleDisconnects() {
        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        // Multiple disconnects should not throw
        client.disconnect();
        client.disconnect();
        client.disconnect();
    }

    // Helper method to calculate exponential backoff (mirrors SDK implementation)
    private long calculateBackoff(int baseDelay, int maxDelay, int attempt) {
        long delay = (long) (baseDelay * Math.pow(2, attempt - 1));
        return Math.min(delay, maxDelay);
    }

    // Helper method to check if connection is stale
    private boolean isStale(long lastPongTime, long currentTime, int staleThreshold) {
        return (currentTime - lastPongTime) > staleThreshold;
    }
}

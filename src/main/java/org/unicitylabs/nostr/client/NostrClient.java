package org.unicitylabs.nostr.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.nametag.NametagBinding;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;
import org.unicitylabs.nostr.protocol.Filter;
import org.unicitylabs.nostr.token.TokenTransferProtocol;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

/**
 * Main Nostr client for connecting to relays, publishing events, and subscribing to events.
 * Supports multiple relay connections, automatic reconnection, and message queuing.
 */
public class NostrClient {

    private static final Logger logger = LoggerFactory.getLogger(NostrClient.class);
    private static final int CONNECTION_TIMEOUT_SECONDS = 30;
    private static final int RECONNECT_DELAY_MS = 5000;

    private final NostrKeyManager keyManager;
    private final OkHttpClient httpClient;
    private final ObjectMapper jsonMapper;

    private final Map<String, RelayConnection> relayConnections = new ConcurrentHashMap<>();
    private final Map<String, SubscriptionInfo> subscriptions = new ConcurrentHashMap<>();
    private final List<QueuedEvent> messageQueue = new CopyOnWriteArrayList<>();

    private boolean isRunning = false;
    private ScheduledExecutorService reconnectExecutor;

    /**
     * Create a Nostr client with key manager.
     *
     * @param keyManager NostrKeyManager for signing and encryption
     */
    public NostrClient(NostrKeyManager keyManager) {
        this.keyManager = keyManager;
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(CONNECTION_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)  // No read timeout for WebSocket
            .writeTimeout(CONNECTION_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .pingInterval(25, TimeUnit.SECONDS)  // Keep connection alive
            .build();
        this.jsonMapper = new ObjectMapper();
        this.reconnectExecutor = Executors.newScheduledThreadPool(1);
    }

    /**
     * Connect to Nostr relays.
     *
     * @param relayUrls Relay WebSocket URLs
     * @return CompletableFuture that completes when all relays are connected
     */
    public CompletableFuture<Void> connect(String... relayUrls) {
        isRunning = true;

        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (String relayUrl : relayUrls) {
            futures.add(connectToRelay(relayUrl));
        }

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
    }

    /**
     * Connect to a single relay.
     */
    private CompletableFuture<Void> connectToRelay(String relayUrl) {
        CompletableFuture<Void> future = new CompletableFuture<>();

        if (relayConnections.containsKey(relayUrl)) {
            logger.debug("Already connected to relay: {}", relayUrl);
            future.complete(null);
            return future;
        }

        logger.info("Connecting to relay: {}", relayUrl);

        Request request = new Request.Builder()
            .url(relayUrl)
            .build();

        RelayConnection connection = new RelayConnection(relayUrl, future);
        WebSocket webSocket = httpClient.newWebSocket(request, connection);
        connection.setWebSocket(webSocket);
        relayConnections.put(relayUrl, connection);

        return future;
    }

    /**
     * Disconnect from all relays.
     */
    public void disconnect() {
        logger.info("Disconnecting from all relays");
        isRunning = false;

        for (RelayConnection connection : relayConnections.values()) {
            connection.close();
        }
        relayConnections.clear();

        if (reconnectExecutor != null) {
            reconnectExecutor.shutdown();
        }
    }

    /**
     * Check if client is connected to any relay.
     */
    public boolean isConnected() {
        return relayConnections.values().stream()
            .anyMatch(RelayConnection::isConnected);
    }

    /**
     * Publish an event to all connected relays.
     *
     * @param event Event to publish
     * @return CompletableFuture with event ID
     */
    public CompletableFuture<String> publishEvent(Event event) {
        CompletableFuture<String> future = new CompletableFuture<>();

        try {
            List<Object> eventMessage = Arrays.asList("EVENT", event);
            String json = jsonMapper.writeValueAsString(eventMessage);

            boolean sentToAny = false;
            for (RelayConnection connection : relayConnections.values()) {
                if (connection.isConnected()) {
                    connection.send(json);
                    sentToAny = true;
                }
            }

            if (sentToAny) {
                future.complete(event.getId());
            } else {
                // Queue for later delivery
                messageQueue.add(new QueuedEvent(event, System.currentTimeMillis()));
                future.completeExceptionally(new Exception("No connected relays, event queued"));
            }
        } catch (Exception e) {
            future.completeExceptionally(e);
        }

        return future;
    }

    /**
     * Publish an encrypted direct message (NIP-04).
     *
     * @param recipientPubkeyHex Recipient's public key (hex)
     * @param message Plaintext message
     * @return CompletableFuture with event ID
     */
    public CompletableFuture<String> publishEncryptedMessage(String recipientPubkeyHex, String message) {
        try {
            long createdAt = System.currentTimeMillis() / 1000;

            // Encrypt content
            String encryptedContent = keyManager.encryptHex(message, recipientPubkeyHex);

            // Create event
            Event event = new Event();
            event.setPubkey(keyManager.getPublicKeyHex());
            event.setCreatedAt(createdAt);
            event.setKind(EventKinds.ENCRYPTED_DM);
            event.setTags(Collections.singletonList(Arrays.asList("p", recipientPubkeyHex)));
            event.setContent(encryptedContent);

            // Calculate ID and sign
            String eventId = calculateEventId(event);
            event.setId(eventId);

            byte[] eventIdBytes = Hex.decodeHex(eventId.toCharArray());
            String signature = keyManager.signHex(eventIdBytes);
            event.setSig(signature);

            return publishEvent(event);
        } catch (Exception e) {
            CompletableFuture<String> future = new CompletableFuture<>();
            future.completeExceptionally(e);
            return future;
        }
    }

    /**
     * Send a token transfer to a recipient.
     *
     * @param recipientPubkeyHex Recipient's Nostr public key (hex)
     * @param tokenJson Unicity SDK token JSON
     * @return CompletableFuture with event ID
     */
    public CompletableFuture<String> sendTokenTransfer(String recipientPubkeyHex, String tokenJson) {
        try {
            Event event = TokenTransferProtocol.createTokenTransferEvent(keyManager, recipientPubkeyHex, tokenJson);
            return publishEvent(event);
        } catch (Exception e) {
            CompletableFuture<String> future = new CompletableFuture<>();
            future.completeExceptionally(e);
            return future;
        }
    }

    /**
     * Publish a nametag binding.
     *
     * @param nametagId Nametag identifier
     * @param unicityAddress Unicity blockchain address
     * @return CompletableFuture indicating success
     */
    public CompletableFuture<Boolean> publishNametagBinding(String nametagId, String unicityAddress) {
        try {
            Event event = NametagBinding.createBindingEvent(keyManager, nametagId, unicityAddress);
            return publishEvent(event).thenApply(eventId -> true);
        } catch (Exception e) {
            CompletableFuture<Boolean> future = new CompletableFuture<>();
            future.completeExceptionally(e);
            return future;
        }
    }

    /**
     * Query Nostr pubkey by nametag.
     *
     * @param nametagId Nametag identifier
     * @return CompletableFuture with pubkey (hex) or null if not found
     */
    public CompletableFuture<String> queryPubkeyByNametag(String nametagId) {
        CompletableFuture<String> future = new CompletableFuture<>();

        Filter filter = NametagBinding.createNametagToPubkeyFilter(nametagId);
        String subscriptionId = "query-" + UUID.randomUUID().toString().substring(0, 8);

        // Temporary listener for this query
        NostrEventListener listener = new NostrEventListener() {
            @Override
            public void onEvent(Event event) {
                if (event.getKind() == EventKinds.APP_DATA) {
                    future.complete(event.getPubkey());
                    unsubscribe(subscriptionId);
                }
            }

            @Override
            public void onEndOfStoredEvents(String subId) {
                if (!future.isDone()) {
                    future.complete(null);
                    unsubscribe(subscriptionId);
                }
            }
        };

        subscribe(subscriptionId, filter, listener);

        // Timeout after 5 seconds
        CompletableFuture.delayedExecutor(5, TimeUnit.SECONDS).execute(() -> {
            if (!future.isDone()) {
                future.complete(null);
                unsubscribe(subscriptionId);
            }
        });

        return future;
    }

    /**
     * Subscribe to events matching a filter.
     *
     * @param filter Filter for subscription
     * @param listener Listener for received events
     * @return Subscription ID
     */
    public String subscribe(Filter filter, NostrEventListener listener) {
        String subscriptionId = UUID.randomUUID().toString().substring(0, 16);
        return subscribe(subscriptionId, filter, listener);
    }

    /**
     * Subscribe with a specific subscription ID.
     */
    public String subscribe(String subscriptionId, Filter filter, NostrEventListener listener) {
        subscriptions.put(subscriptionId, new SubscriptionInfo(filter, listener));

        try {
            List<Object> reqMessage = new ArrayList<>();
            reqMessage.add("REQ");
            reqMessage.add(subscriptionId);
            reqMessage.add(filter);

            String json = jsonMapper.writeValueAsString(reqMessage);

            for (RelayConnection connection : relayConnections.values()) {
                if (connection.isConnected()) {
                    connection.send(json);
                }
            }

            logger.debug("Subscribed with ID: {}", subscriptionId);
        } catch (Exception e) {
            logger.error("Failed to subscribe", e);
        }

        return subscriptionId;
    }

    /**
     * Unsubscribe from events.
     *
     * @param subscriptionId Subscription ID
     */
    public void unsubscribe(String subscriptionId) {
        subscriptions.remove(subscriptionId);

        try {
            List<Object> closeMessage = Arrays.asList("CLOSE", subscriptionId);
            String json = jsonMapper.writeValueAsString(closeMessage);

            for (RelayConnection connection : relayConnections.values()) {
                if (connection.isConnected()) {
                    connection.send(json);
                }
            }

            logger.debug("Unsubscribed: {}", subscriptionId);
        } catch (Exception e) {
            logger.error("Failed to unsubscribe", e);
        }
    }

    /**
     * Get the key manager.
     */
    public NostrKeyManager getKeyManager() {
        return keyManager;
    }

    /**
     * Get connected relay URLs.
     */
    public Set<String> getConnectedRelays() {
        Set<String> connected = new HashSet<>();
        for (Map.Entry<String, RelayConnection> entry : relayConnections.entrySet()) {
            if (entry.getValue().isConnected()) {
                connected.add(entry.getKey());
            }
        }
        return connected;
    }

    // Helper methods

    private String calculateEventId(Event event) throws Exception {
        List<Object> eventData = Arrays.asList(
            0,
            event.getPubkey(),
            event.getCreatedAt(),
            event.getKind(),
            event.getTags(),
            event.getContent()
        );

        String eventJson = jsonMapper.writeValueAsString(eventData);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(eventJson.getBytes(StandardCharsets.UTF_8));

        return new String(Hex.encodeHex(hashBytes));
    }

    // Inner classes

    private class RelayConnection extends WebSocketListener {
        private final String url;
        private final CompletableFuture<Void> connectFuture;
        private WebSocket webSocket;
        private boolean connected = false;

        RelayConnection(String url, CompletableFuture<Void> connectFuture) {
            this.url = url;
            this.connectFuture = connectFuture;
        }

        void setWebSocket(WebSocket webSocket) {
            this.webSocket = webSocket;
        }

        boolean isConnected() {
            return connected;
        }

        void send(String message) {
            if (webSocket != null && connected) {
                webSocket.send(message);
            }
        }

        void close() {
            if (webSocket != null) {
                webSocket.close(1000, "Client disconnect");
                connected = false;
            }
        }

        @Override
        public void onOpen(WebSocket webSocket, Response response) {
            connected = true;
            logger.info("Connected to relay: {}", url);
            connectFuture.complete(null);

            // Flush queued messages
            for (QueuedEvent queued : messageQueue) {
                try {
                    List<Object> eventMessage = Arrays.asList("EVENT", queued.event);
                    String json = jsonMapper.writeValueAsString(eventMessage);
                    webSocket.send(json);
                } catch (Exception e) {
                    logger.error("Failed to send queued event", e);
                }
            }
            messageQueue.clear();

            // Re-establish subscriptions
            for (Map.Entry<String, SubscriptionInfo> entry : subscriptions.entrySet()) {
                try {
                    List<Object> reqMessage = new ArrayList<>();
                    reqMessage.add("REQ");
                    reqMessage.add(entry.getKey());
                    reqMessage.add(entry.getValue().filter);

                    String json = jsonMapper.writeValueAsString(reqMessage);
                    webSocket.send(json);
                } catch (Exception e) {
                    logger.error("Failed to re-establish subscription", e);
                }
            }
        }

        @Override
        public void onMessage(WebSocket webSocket, String text) {
            try {
                handleRelayMessage(text);
            } catch (Exception e) {
                logger.error("Error handling relay message", e);
            }
        }

        @Override
        public void onFailure(WebSocket webSocket, Throwable t, Response response) {
            connected = false;

            // Don't log EOFException as ERROR during intentional disconnect
            // EOFException happens when we close the socket during disconnect()
            boolean isEOF = t instanceof java.io.EOFException;
            boolean isIntentionalDisconnect = !isRunning;

            if (isEOF && isIntentionalDisconnect) {
                // Normal disconnect, just debug log
                logger.debug("WebSocket closed during disconnect: {}", url);
            } else if (isEOF) {
                // EOF during active connection (relay closed unexpectedly)
                logger.warn("Relay closed connection unexpectedly: {}", url);
            } else {
                // Actual error (not EOF)
                logger.error("Relay connection failed: {}", url, t);
            }

            if (!connectFuture.isDone()) {
                connectFuture.completeExceptionally(t);
            }

            // Schedule reconnect if still running
            if (isRunning) {
                reconnectExecutor.schedule(() -> connectToRelay(url), RECONNECT_DELAY_MS, TimeUnit.MILLISECONDS);
            }
        }

        @Override
        public void onClosed(WebSocket webSocket, int code, String reason) {
            connected = false;
            logger.info("Relay closed: {} - {}", url, reason);

            // Schedule reconnect if still running
            if (isRunning) {
                reconnectExecutor.schedule(() -> connectToRelay(url), RECONNECT_DELAY_MS, TimeUnit.MILLISECONDS);
            }
        }
    }

    private void handleRelayMessage(String message) {
        try {
            @SuppressWarnings("unchecked")
            List<Object> json = jsonMapper.readValue(message, List.class);

            String messageType = (String) json.get(0);

            switch (messageType) {
                case "EVENT":
                    handleEventMessage(json);
                    break;
                case "OK":
                    handleOkMessage(json);
                    break;
                case "EOSE":
                    handleEOSEMessage(json);
                    break;
                case "NOTICE":
                    handleNoticeMessage(json);
                    break;
                default:
                    logger.debug("Unknown message type: {}", messageType);
            }
        } catch (Exception e) {
            logger.error("Error parsing relay message", e);
        }
    }

    private void handleEventMessage(List<Object> json) {
        try {
            String subscriptionId = (String) json.get(1);
            @SuppressWarnings("unchecked")
            Map<String, Object> eventData = (Map<String, Object>) json.get(2);

            Event event = jsonMapper.convertValue(eventData, Event.class);

            SubscriptionInfo subscription = subscriptions.get(subscriptionId);
            if (subscription != null && subscription.listener != null) {
                subscription.listener.onEvent(event);
            }
        } catch (Exception e) {
            logger.error("Error handling EVENT message", e);
        }
    }

    private void handleOkMessage(List<Object> json) {
        String eventId = json.size() > 1 ? (String) json.get(1) : "unknown";
        boolean success = json.size() > 2 && (Boolean) json.get(2);
        String statusMessage = json.size() > 3 ? (String) json.get(3) : "";

        if (success) {
            logger.debug("Event accepted: {}", eventId);
        } else {
            logger.warn("Event rejected: {} - {}", eventId, statusMessage);
        }
    }

    private void handleEOSEMessage(List<Object> json) {
        String subscriptionId = (String) json.get(1);
        SubscriptionInfo subscription = subscriptions.get(subscriptionId);
        if (subscription != null && subscription.listener != null) {
            subscription.listener.onEndOfStoredEvents(subscriptionId);
        }
        logger.debug("EOSE for subscription: {}", subscriptionId);
    }

    private void handleNoticeMessage(List<Object> json) {
        String notice = json.size() > 1 ? (String) json.get(1) : "";
        logger.info("Relay notice: {}", notice);
    }

    private static class SubscriptionInfo {
        final Filter filter;
        final NostrEventListener listener;

        SubscriptionInfo(Filter filter, NostrEventListener listener) {
            this.filter = filter;
            this.listener = listener;
        }
    }

    private static class QueuedEvent {
        final Event event;
        final long timestamp;

        QueuedEvent(Event event, long timestamp) {
            this.event = event;
            this.timestamp = timestamp;
        }
    }
}

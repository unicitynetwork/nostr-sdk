package org.unicitylabs.nostr.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.nametag.NametagBinding;
import org.unicitylabs.nostr.nametag.NametagUtils;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;
import org.unicitylabs.nostr.protocol.Filter;
import org.unicitylabs.nostr.token.TokenTransferProtocol;
import org.unicitylabs.nostr.payment.PaymentRequestProtocol;
import org.unicitylabs.nostr.messaging.NIP17Protocol;
import org.unicitylabs.nostr.messaging.PrivateMessage;

import java.math.BigInteger;
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
    private static final int DEFAULT_QUERY_TIMEOUT_MS = 5000;
    private static final int DEFAULT_RECONNECT_INTERVAL_MS = 1000;
    private static final int DEFAULT_MAX_RECONNECT_INTERVAL_MS = 30000;
    private static final int DEFAULT_PING_INTERVAL_MS = 30000;

    private final NostrKeyManager keyManager;
    private final OkHttpClient httpClient;
    private final ObjectMapper jsonMapper;

    private final Map<String, RelayConnection> relayConnections = new ConcurrentHashMap<>();
    private final Map<String, SubscriptionInfo> subscriptions = new ConcurrentHashMap<>();
    private final List<QueuedEvent> messageQueue = new CopyOnWriteArrayList<>();
    private final List<ConnectionEventListener> connectionListeners = new CopyOnWriteArrayList<>();

    private boolean isRunning = false;
    private ScheduledExecutorService reconnectExecutor;

    // Configuration options
    private int queryTimeoutMs = DEFAULT_QUERY_TIMEOUT_MS;
    private boolean autoReconnect = true;
    private int reconnectIntervalMs = DEFAULT_RECONNECT_INTERVAL_MS;
    private int maxReconnectIntervalMs = DEFAULT_MAX_RECONNECT_INTERVAL_MS;
    private int pingIntervalMs = DEFAULT_PING_INTERVAL_MS;

    /**
     * Connection event listener for monitoring relay connections.
     */
    public interface ConnectionEventListener {
        /** Called when a relay connection is established. */
        default void onConnect(String relayUrl) {}
        /** Called when a relay connection is lost. */
        default void onDisconnect(String relayUrl, String reason) {}
        /** Called when reconnection is being attempted. */
        default void onReconnecting(String relayUrl, int attempt) {}
        /** Called when reconnection succeeds. */
        default void onReconnected(String relayUrl) {}
    }

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
            .pingInterval(pingIntervalMs > 0 ? pingIntervalMs : 25000, TimeUnit.MILLISECONDS)  // OkHttp built-in ping
            .build();
        this.jsonMapper = new ObjectMapper();
        this.reconnectExecutor = Executors.newScheduledThreadPool(1);
    }

    /**
     * Add a connection event listener.
     *
     * @param listener Listener for connection events
     */
    public void addConnectionListener(ConnectionEventListener listener) {
        connectionListeners.add(listener);
    }

    /**
     * Remove a connection event listener.
     *
     * @param listener Listener to remove
     */
    public void removeConnectionListener(ConnectionEventListener listener) {
        connectionListeners.remove(listener);
    }

    /**
     * Set whether automatic reconnection is enabled.
     *
     * @param autoReconnect true to enable auto-reconnect (default: true)
     */
    public void setAutoReconnect(boolean autoReconnect) {
        this.autoReconnect = autoReconnect;
    }

    /**
     * Set the initial reconnect interval.
     *
     * @param intervalMs Initial reconnect interval in milliseconds
     */
    public void setReconnectIntervalMs(int intervalMs) {
        this.reconnectIntervalMs = intervalMs;
    }

    /**
     * Set the maximum reconnect interval (for exponential backoff).
     *
     * @param maxIntervalMs Maximum reconnect interval in milliseconds
     */
    public void setMaxReconnectIntervalMs(int maxIntervalMs) {
        this.maxReconnectIntervalMs = maxIntervalMs;
    }

    /**
     * Set the ping interval for health checks.
     *
     * @param intervalMs Ping interval in milliseconds (0 to disable)
     */
    public void setPingIntervalMs(int intervalMs) {
        this.pingIntervalMs = intervalMs;
    }

    /**
     * Emit a connection event to all listeners.
     */
    private void emitConnectionEvent(String eventType, String relayUrl, Object extra) {
        for (ConnectionEventListener listener : connectionListeners) {
            try {
                switch (eventType) {
                    case "connect":
                        listener.onConnect(relayUrl);
                        break;
                    case "disconnect":
                        listener.onDisconnect(relayUrl, (String) extra);
                        break;
                    case "reconnecting":
                        listener.onReconnecting(relayUrl, (Integer) extra);
                        break;
                    case "reconnected":
                        listener.onReconnected(relayUrl);
                        break;
                }
            } catch (Exception e) {
                logger.warn("Error in connection listener", e);
            }
        }
    }

    /**
     * Get the current query timeout in milliseconds.
     *
     * @return Query timeout in milliseconds
     */
    public int getQueryTimeoutMs() {
        return queryTimeoutMs;
    }

    /**
     * Set the query timeout for nametag lookups and other queries.
     *
     * @param timeoutMs Timeout in milliseconds
     */
    public void setQueryTimeoutMs(int timeoutMs) {
        this.queryTimeoutMs = timeoutMs;
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
     *
     * @return true if connected to at least one relay
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
     * Send a private direct message using NIP-17 gift wrapping.
     * Uses NIP-44 encryption and ephemeral keys for sender anonymity.
     *
     * @param recipientPubkeyHex Recipient's public key (hex)
     * @param message Plaintext message
     * @return CompletableFuture with gift wrap event ID
     */
    public CompletableFuture<String> sendPrivateMessage(String recipientPubkeyHex, String message) {
        return sendPrivateMessage(recipientPubkeyHex, message, null);
    }

    /**
     * Send a private direct message with optional reply reference.
     *
     * @param recipientPubkeyHex Recipient's public key (hex)
     * @param message Plaintext message
     * @param replyToEventId Optional event ID to reply to
     * @return CompletableFuture with gift wrap event ID
     */
    public CompletableFuture<String> sendPrivateMessage(String recipientPubkeyHex, String message,
                                                         String replyToEventId) {
        return sendPrivateMessage(recipientPubkeyHex, message, replyToEventId, null);
    }

    /**
     * Send a private direct message with sender nametag identification.
     *
     * @param recipientPubkeyHex Recipient's public key (hex)
     * @param message Plaintext message
     * @param replyToEventId Optional event ID to reply to
     * @param senderNametag Optional sender's nametag (Unicity ID) for identification
     * @return CompletableFuture with gift wrap event ID
     */
    public CompletableFuture<String> sendPrivateMessage(String recipientPubkeyHex, String message,
                                                         String replyToEventId, String senderNametag) {
        try {
            Event giftWrap = NIP17Protocol.createGiftWrap(keyManager, recipientPubkeyHex, message,
                    replyToEventId, senderNametag);
            return publishEvent(giftWrap);
        } catch (Exception e) {
            CompletableFuture<String> future = new CompletableFuture<>();
            future.completeExceptionally(e);
            return future;
        }
    }

    /**
     * Send a private message to a recipient identified by their nametag.
     * Resolves the nametag to a pubkey automatically.
     *
     * @param recipientNametag Recipient's nametag (Unicity ID)
     * @param message Plaintext message
     * @param senderNametag Optional sender's nametag for identification
     * @return CompletableFuture with gift wrap event ID
     */
    public CompletableFuture<String> sendPrivateMessageToNametag(String recipientNametag, String message,
                                                                   String senderNametag) {
        return queryPubkeyByNametag(recipientNametag)
            .thenCompose(pubkey -> {
                if (pubkey == null) {
                    CompletableFuture<String> failed = new CompletableFuture<>();
                    failed.completeExceptionally(
                        new Exception("Nametag not found: " + recipientNametag));
                    return failed;
                }
                return sendPrivateMessage(pubkey, message, null, senderNametag);
            });
    }

    /**
     * Send a private message to a recipient identified by their nametag.
     * Resolves the nametag to a pubkey automatically.
     *
     * @param recipientNametag Recipient's nametag (Unicity ID)
     * @param message Plaintext message
     * @return CompletableFuture with gift wrap event ID
     */
    public CompletableFuture<String> sendPrivateMessageToNametag(String recipientNametag, String message) {
        return sendPrivateMessageToNametag(recipientNametag, message, null);
    }

    /**
     * Send a read receipt for a message.
     *
     * @param recipientPubkeyHex Original sender's public key (who will receive the receipt)
     * @param messageEventId Event ID of the message being acknowledged
     * @return CompletableFuture with gift wrap event ID
     */
    public CompletableFuture<String> sendReadReceipt(String recipientPubkeyHex, String messageEventId) {
        try {
            Event giftWrap = NIP17Protocol.createReadReceipt(keyManager, recipientPubkeyHex, messageEventId);
            return publishEvent(giftWrap);
        } catch (Exception e) {
            CompletableFuture<String> future = new CompletableFuture<>();
            future.completeExceptionally(e);
            return future;
        }
    }

    /**
     * Unwrap a received gift-wrapped private message.
     *
     * @param giftWrap Gift wrap event (kind 1059)
     * @return Parsed private message
     * @throws Exception if unwrapping fails
     */
    public PrivateMessage unwrapPrivateMessage(Event giftWrap) throws Exception {
        return NIP17Protocol.unwrap(giftWrap, keyManager);
    }

    /**
     * Send a token transfer to a recipient.
     *
     * @param recipientPubkeyHex Recipient's Nostr public key (hex)
     * @param tokenJson Unicity SDK token JSON
     * @return CompletableFuture with event ID
     */
    public CompletableFuture<String> sendTokenTransfer(String recipientPubkeyHex, String tokenJson) {
        return sendTokenTransfer(recipientPubkeyHex, tokenJson, null, null, null);
    }

    /**
     * Send a token transfer to a recipient in response to a payment request.
     *
     * @param recipientPubkeyHex Recipient's Nostr public key (hex)
     * @param tokenJson Unicity SDK token JSON
     * @param amount Optional amount for metadata (BigInteger for large values)
     * @param symbol Optional symbol for metadata
     * @param replyToEventId Optional event ID this transfer is responding to (e.g., payment request)
     * @return CompletableFuture with event ID
     */
    public CompletableFuture<String> sendTokenTransfer(String recipientPubkeyHex, String tokenJson,
                                                        BigInteger amount, String symbol, String replyToEventId) {
        try {
            Event event = TokenTransferProtocol.createTokenTransferEvent(
                keyManager, recipientPubkeyHex, tokenJson, amount, symbol, replyToEventId);
            return publishEvent(event);
        } catch (Exception e) {
            CompletableFuture<String> future = new CompletableFuture<>();
            future.completeExceptionally(e);
            return future;
        }
    }

    /**
     * Send a payment request to a target.
     *
     * @param targetPubkeyHex Target's Nostr public key (who should pay)
     * @param request Payment request details
     * @return CompletableFuture with event ID
     */
    public CompletableFuture<String> sendPaymentRequest(String targetPubkeyHex,
                                                         PaymentRequestProtocol.PaymentRequest request) {
        try {
            Event event = PaymentRequestProtocol.createPaymentRequestEvent(keyManager, targetPubkeyHex, request);
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
            String hashedNametag = NametagUtils.hashNametag(nametagId);
            logger.info("Publishing nametag binding: '{}' (hashed: {}...) -> pubkey {}...",
                nametagId, hashedNametag.substring(0, 16), keyManager.getPublicKeyHex().substring(0, 16));
            Event event = NametagBinding.createBindingEvent(keyManager, nametagId, unicityAddress);
            return publishEvent(event).thenApply(eventId -> {
                logger.info("Nametag binding published successfully: eventId={}...", eventId.substring(0, 16));
                return true;
            });
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

        // Log the query for debugging
        String hashedNametag = NametagUtils.hashNametag(nametagId);
        logger.info("Querying nametag '{}' (hashed: {}...)", nametagId, hashedNametag.substring(0, 16));

        Filter filter = NametagBinding.createNametagToPubkeyFilter(nametagId);
        String subscriptionId = "query-" + UUID.randomUUID().toString().substring(0, 8);

        // Temporary listener for this query
        NostrEventListener listener = new NostrEventListener() {
            @Override
            public void onEvent(Event event) {
                logger.debug("Nametag query got event: kind={}, pubkey={}...",
                    event.getKind(), event.getPubkey().substring(0, 16));
                if (event.getKind() == EventKinds.APP_DATA) {
                    logger.info("Found nametag binding for '{}', pubkey: {}...",
                        nametagId, event.getPubkey().substring(0, 16));
                    future.complete(event.getPubkey());
                    unsubscribe(subscriptionId);
                }
            }

            @Override
            public void onEndOfStoredEvents(String subId) {
                if (!future.isDone()) {
                    logger.warn("Nametag '{}' not found (EOSE received with no results)", nametagId);
                    future.complete(null);
                    unsubscribe(subscriptionId);
                }
            }
        };

        subscribe(subscriptionId, filter, listener);

        // Timeout using configurable queryTimeoutMs
        CompletableFuture.delayedExecutor(queryTimeoutMs, TimeUnit.MILLISECONDS).execute(() -> {
            if (!future.isDone()) {
                logger.warn("Nametag '{}' query timed out after {}ms", nametagId, queryTimeoutMs);
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
     *
     * @param subscriptionId the subscription ID to use
     * @param filter the filter for events
     * @param listener the listener for received events
     * @return the subscription ID
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
     *
     * @return the key manager
     */
    public NostrKeyManager getKeyManager() {
        return keyManager;
    }

    /**
     * Get connected relay URLs.
     *
     * @return set of connected relay URLs
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
        private CompletableFuture<Void> connectFuture;
        private WebSocket webSocket;
        private boolean connected = false;
        private boolean wasConnected = false;
        private int reconnectAttempts = 0;

        RelayConnection(String url, CompletableFuture<Void> connectFuture) {
            this.url = url;
            this.connectFuture = connectFuture;
        }

        void setConnectFuture(CompletableFuture<Void> future) {
            this.connectFuture = future;
        }

        void resetReconnectAttempts() {
            this.reconnectAttempts = 0;
        }

        int incrementReconnectAttempts() {
            return ++this.reconnectAttempts;
        }

        int getReconnectAttempts() {
            return reconnectAttempts;
        }

        boolean wasConnectedBefore() {
            return wasConnected;
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
            boolean wasReconnecting = wasConnected;
            wasConnected = true;

            if (wasReconnecting) {
                logger.info("Reconnected to relay: {}", url);
                emitConnectionEvent("reconnected", url, null);
            } else {
                logger.info("Connected to relay: {}", url);
                emitConnectionEvent("connect", url, null);
            }

            // Reset reconnect attempts on successful connection
            resetReconnectAttempts();

            if (connectFuture != null && !connectFuture.isDone()) {
                connectFuture.complete(null);
            }

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
            boolean wasConnectedBefore = connected;
            connected = false;

            // Don't log EOFException as ERROR during intentional disconnect
            // EOFException happens when we close the socket during disconnect()
            boolean isEOF = t instanceof java.io.EOFException;
            boolean isIntentionalDisconnect = !isRunning;

            String reason = t != null ? t.getMessage() : "Unknown error";

            if (isEOF && isIntentionalDisconnect) {
                // Normal disconnect, just debug log
                logger.debug("WebSocket closed during disconnect: {}", url);
            } else if (isEOF) {
                // EOF during active connection (relay closed unexpectedly)
                logger.warn("Relay closed connection unexpectedly: {}", url);
                reason = "Connection closed unexpectedly";
            } else {
                // Actual error (not EOF)
                logger.error("Relay connection failed: {}", url, t);
            }

            // Emit disconnect event if we were connected
            if (wasConnectedBefore) {
                emitConnectionEvent("disconnect", url, reason);
            }

            if (connectFuture != null && !connectFuture.isDone()) {
                connectFuture.completeExceptionally(t);
            }

            // Schedule reconnect with exponential backoff if still running
            scheduleReconnect();
        }

        private void scheduleReconnect() {
            if (!isRunning || !autoReconnect) {
                return;
            }

            int attempt = incrementReconnectAttempts();

            // Calculate delay with exponential backoff: baseDelay * 2^(attempts-1)
            long delay = (long) (reconnectIntervalMs * Math.pow(2, attempt - 1));
            delay = Math.min(delay, maxReconnectIntervalMs);

            logger.info("Scheduling reconnect to {} in {}ms (attempt {})", url, delay, attempt);
            emitConnectionEvent("reconnecting", url, attempt);

            reconnectExecutor.schedule(() -> {
                if (isRunning && autoReconnect) {
                    reconnectToRelay();
                }
            }, delay, TimeUnit.MILLISECONDS);
        }

        private void reconnectToRelay() {
            logger.info("Attempting to reconnect to relay: {}", url);

            Request request = new Request.Builder()
                .url(url)
                .build();

            // Create a new future for this reconnect attempt
            CompletableFuture<Void> reconnectFuture = new CompletableFuture<>();
            setConnectFuture(reconnectFuture);

            WebSocket newWebSocket = httpClient.newWebSocket(request, this);
            setWebSocket(newWebSocket);
        }

        @Override
        public void onClosed(WebSocket webSocket, int code, String reason) {
            connected = false;
            logger.info("Relay closed: {} - {} (code: {})", url, reason, code);

            // Emit disconnect event
            emitConnectionEvent("disconnect", url, reason != null ? reason : "Connection closed");

            // Schedule reconnect with exponential backoff if still running
            scheduleReconnect();
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

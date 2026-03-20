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
     * Send a payment request response (decline/expiration notification).
     *
     * @param targetPubkeyHex Target's Nostr public key (original request sender)
     * @param response Payment request response
     * @return CompletableFuture with event ID
     */
    public CompletableFuture<String> sendPaymentRequestResponse(String targetPubkeyHex,
                                                                  PaymentRequestProtocol.PaymentRequestResponse response) {
        try {
            Event event = PaymentRequestProtocol.createPaymentRequestResponseEvent(keyManager, targetPubkeyHex, response);
            return publishEvent(event);
        } catch (Exception e) {
            CompletableFuture<String> future = new CompletableFuture<>();
            future.completeExceptionally(e);
            return future;
        }
    }

    /**
     * Send a payment request decline response.
     * Convenience method for declining a payment request.
     *
     * @param originalRequestSenderPubkey Pubkey of who sent the original payment request
     * @param originalEventId Event ID of the original payment request
     * @param requestId Request ID from the original payment request
     * @param reason Optional reason for declining
     * @return CompletableFuture with event ID
     */
    public CompletableFuture<String> sendPaymentRequestDecline(String originalRequestSenderPubkey,
                                                                 String originalEventId,
                                                                 String requestId,
                                                                 String reason) {
        PaymentRequestProtocol.PaymentRequestResponse response = new PaymentRequestProtocol.PaymentRequestResponse(
            requestId,
            originalEventId,
            PaymentRequestProtocol.ResponseStatus.DECLINED,
            reason
        );
        return sendPaymentRequestResponse(originalRequestSenderPubkey, response);
    }

    /**
     * Publish a nametag binding.
     * Checks for existing claims by other pubkeys before publishing.
     *
     * @param nametagId Nametag identifier
     * @param unicityAddress Unicity blockchain address
     * @return CompletableFuture indicating success (completes exceptionally if claimed by another pubkey)
     */
    public CompletableFuture<Boolean> publishNametagBinding(String nametagId, String unicityAddress) {
        return publishNametagBinding(nametagId, unicityAddress, null);
    }

    /**
     * Publish a nametag binding with optional identity parameters.
     * Checks for existing claims by other pubkeys before publishing.
     *
     * @param nametagId Nametag identifier
     * @param unicityAddress Unicity blockchain address
     * @param identity Optional extended identity parameters
     * @return CompletableFuture indicating success (completes exceptionally if claimed by another pubkey)
     */
    public CompletableFuture<Boolean> publishNametagBinding(String nametagId, String unicityAddress,
                                                              NametagBinding.IdentityBindingParams identity) {
        return queryPubkeyByNametag(nametagId).thenCompose(existingOwner -> {
            if (existingOwner != null && !existingOwner.equals(keyManager.getPublicKeyHex())) {
                CompletableFuture<Boolean> failed = new CompletableFuture<>();
                failed.completeExceptionally(new Exception(
                    "Nametag \"" + nametagId + "\" is already claimed by another pubkey"));
                return failed;
            }

            try {
                String hashedNametag = NametagUtils.hashNametag(nametagId);
                logger.info("Publishing nametag binding: '{}' (hashed: {}...) -> pubkey {}...",
                    nametagId, hashedNametag.substring(0, 16), keyManager.getPublicKeyHex().substring(0, 16));
                Event event = NametagBinding.createBindingEvent(keyManager, nametagId, unicityAddress, "US", identity);
                return publishEvent(event).thenApply(eventId -> {
                    logger.info("Nametag binding published successfully: eventId={}...",
                        eventId.substring(0, Math.min(16, eventId.length())));
                    return true;
                });
            } catch (Exception e) {
                CompletableFuture<Boolean> failed = new CompletableFuture<>();
                failed.completeExceptionally(e);
                return failed;
            }
        });
    }

    /**
     * Publish a base identity binding (no nametag).
     * Uses d-tag = SHA256('unicity:identity:' + nostrPubkey) so each wallet
     * has exactly one identity binding. Subsequent calls replace the previous event.
     *
     * @param identity Identity parameters (publicKey, l1Address, directAddress)
     * @return CompletableFuture indicating success
     */
    public CompletableFuture<Boolean> publishIdentityBinding(NametagBinding.IdentityBindingParams identity) {
        try {
            Event event = NametagBinding.createIdentityBindingEvent(keyManager, identity);
            return publishEvent(event).thenApply(eventId -> true);
        } catch (Exception e) {
            CompletableFuture<Boolean> future = new CompletableFuture<>();
            future.completeExceptionally(e);
            return future;
        }
    }

    /**
     * Query Nostr pubkey by nametag.
     * Uses first-seen-wins anti-hijacking resolution.
     *
     * @param nametagId Nametag identifier
     * @return CompletableFuture with pubkey (hex) or null if not found
     */
    public CompletableFuture<String> queryPubkeyByNametag(String nametagId) {
        String hashedNametag = NametagUtils.hashNametag(nametagId);
        logger.info("Querying nametag '{}' (hashed: {}...)", nametagId, hashedNametag.substring(0, 16));

        Filter filter = NametagBinding.createNametagToPubkeyFilter(nametagId);
        return queryWithFirstSeenWins(filter, Event::getPubkey);
    }

    /**
     * Query for full binding info by nametag.
     * Returns extended identity fields (chain pubkey, addresses, etc.) when available.
     * Uses first-seen-wins across authors, latest-wins for same author.
     *
     * @param nametagId Nametag identifier
     * @return CompletableFuture with BindingInfo, or null if not found
     */
    public CompletableFuture<NametagBinding.BindingInfo> queryBindingByNametag(String nametagId) {
        Filter filter = NametagBinding.createNametagToPubkeyFilter(nametagId);
        return queryWithFirstSeenWins(filter, NametagBinding::parseBindingInfo);
    }

    /**
     * Query for binding info by address (reverse lookup).
     * Supports DIRECT://, PROXY://, alpha1..., or chain pubkey lookups.
     * Uses first-seen-wins across authors, latest-wins for same author.
     *
     * @param address Address string
     * @return CompletableFuture with BindingInfo, or null if not found
     */
    public CompletableFuture<NametagBinding.BindingInfo> queryBindingByAddress(String address) {
        Filter filter = NametagBinding.createAddressToBindingFilter(address);
        return queryWithFirstSeenWins(filter, NametagBinding::parseBindingInfo);
    }

    /**
     * Query binding events with first-seen-wins anti-hijacking resolution.
     *
     * Strategy: first-seen-wins across authors, latest-wins for same author.
     * - Across authors: the pubkey that first published wins (earliest created_at)
     * - Same author: the most recent event is used (latest created_at = most complete data)
     * - Tie-breaking: deterministic by lexicographic pubkey comparison (lowest wins)
     *
     * Events with invalid signatures are silently skipped to prevent relay injection attacks.
     *
     * @param filter Subscription filter
     * @param extractResult Function to extract the desired result from the winning event
     * @return CompletableFuture resolving to the extracted result, or null
     */
    private <T> CompletableFuture<T> queryWithFirstSeenWins(Filter filter,
                                                             java.util.function.Function<Event, T> extractResult) {
        CompletableFuture<T> future = new CompletableFuture<>();
        String subscriptionId = "query-" + UUID.randomUUID().toString().substring(0, 8);

        // Track per-author earliest seen and latest event
        Map<String, long[]> authorFirstSeen = new ConcurrentHashMap<>(); // pubkey -> [firstSeen]
        Map<String, Event> authorLatestEvent = new ConcurrentHashMap<>(); // pubkey -> latestEvent

        NostrEventListener listener = new NostrEventListener() {
            @Override
            public void onEvent(Event event) {
                // Verify signature to prevent relay injection of forged events
                if (!event.verify()) {
                    logger.debug("Skipping event with invalid signature: {}", event.getId());
                    return;
                }

                String pubkey = event.getPubkey();
                long createdAt = event.getCreatedAt();

                authorFirstSeen.compute(pubkey, (k, v) -> {
                    if (v == null) return new long[]{createdAt};
                    v[0] = Math.min(v[0], createdAt);
                    return v;
                });

                authorLatestEvent.compute(pubkey, (k, existing) -> {
                    if (existing == null || createdAt > existing.getCreatedAt()) {
                        return event;
                    }
                    return existing;
                });
            }

            @Override
            public void onEndOfStoredEvents(String subId) {
                unsubscribe(subscriptionId);

                if (authorFirstSeen.isEmpty()) {
                    future.complete(null);
                    return;
                }

                // Find the winner: earliest firstSeen, then lexicographic pubkey for tie-break
                String winnerPubkey = null;
                long winnerFirstSeen = Long.MAX_VALUE;
                for (Map.Entry<String, long[]> entry : authorFirstSeen.entrySet()) {
                    String pubkey = entry.getKey();
                    long firstSeen = entry.getValue()[0];
                    if (firstSeen < winnerFirstSeen
                        || (firstSeen == winnerFirstSeen && (winnerPubkey == null || pubkey.compareTo(winnerPubkey) < 0))) {
                        winnerFirstSeen = firstSeen;
                        winnerPubkey = pubkey;
                    }
                }

                Event winnerEvent = authorLatestEvent.get(winnerPubkey);
                future.complete(winnerEvent != null ? extractResult.apply(winnerEvent) : null);
            }
        };

        subscribe(subscriptionId, filter, listener);

        // Timeout
        CompletableFuture.delayedExecutor(queryTimeoutMs, TimeUnit.MILLISECONDS).execute(() -> {
            if (!future.isDone()) {
                logger.warn("Query timed out after {}ms", queryTimeoutMs);
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
        private volatile long lastPongTime = System.currentTimeMillis();
        private volatile long lastPingSentTime = 0;
        private ScheduledFuture<?> pingTimer = null;

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
            stopPingTimer();
            if (webSocket != null) {
                webSocket.close(1000, "Client disconnect");
                connected = false;
            }
        }

        void startPingTimer() {
            stopPingTimer();
            if (pingIntervalMs <= 0) return;

            pingTimer = reconnectExecutor.scheduleAtFixedRate(() -> {
                if (!connected || webSocket == null) {
                    stopPingTimer();
                    return;
                }

                long now = System.currentTimeMillis();
                long timeSinceLastPong = now - lastPongTime;

                if (timeSinceLastPong > pingIntervalMs * 2L) {
                    // Only declare stale if we actually sent a ping recently.
                    // If the timer was delayed (e.g., Android doze mode), we haven't sent
                    // a ping recently, so we can't conclude the relay is stale — just send
                    // a new ping and check again on the next interval.
                    long timeSinceLastPing = now - lastPingSentTime;
                    if (lastPingSentTime > 0 && timeSinceLastPing < pingIntervalMs * 1.5) {
                        // We sent a ping recently and got no response - connection is truly stale
                        logger.warn("Relay {} appears stale (no response for {}ms), reconnecting...", url, timeSinceLastPong);
                        stopPingTimer();
                        try {
                            webSocket.cancel();
                        } catch (Exception e) {
                            // Ignore close errors
                        }
                        return;
                    }
                    // Timer was likely delayed — fall through to send a ping
                }

                // Send a subscription request as a ping (relays respond with EOSE)
                try {
                    String closeMessage = jsonMapper.writeValueAsString(Arrays.asList("CLOSE", "ping"));
                    webSocket.send(closeMessage);
                    String pingMessage = jsonMapper.writeValueAsString(Arrays.asList("REQ", "ping", Collections.singletonMap("limit", 1)));
                    webSocket.send(pingMessage);
                    lastPingSentTime = now;
                } catch (Exception e) {
                    logger.warn("Ping to {} failed, reconnecting...", url);
                    stopPingTimer();
                    try {
                        webSocket.cancel();
                    } catch (Exception ex) {
                        // Ignore close errors
                    }
                }
            }, pingIntervalMs, pingIntervalMs, TimeUnit.MILLISECONDS);
        }

        void stopPingTimer() {
            if (pingTimer != null) {
                pingTimer.cancel(false);
                pingTimer = null;
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
            lastPongTime = System.currentTimeMillis();
            lastPingSentTime = 0;

            // Start application-level ping health check
            startPingTimer();

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
            sendAllSubscriptions(webSocket);
        }

        private void sendSubscription(WebSocket webSocket, String subscriptionId, Filter filter) {
            try {
                List<Object> reqMessage = new ArrayList<>();
                reqMessage.add("REQ");
                reqMessage.add(subscriptionId);
                reqMessage.add(filter);

                String json = jsonMapper.writeValueAsString(reqMessage);
                webSocket.send(json);
            } catch (Exception e) {
                logger.error("Failed to send subscription {}", subscriptionId, e);
            }
        }

        private void sendAllSubscriptions(WebSocket webSocket) {
            for (Map.Entry<String, SubscriptionInfo> entry : subscriptions.entrySet()) {
                sendSubscription(webSocket, entry.getKey(), entry.getValue().filter);
            }
        }

        @Override
        public void onMessage(WebSocket webSocket, String text) {
            // Update last pong time on any message (relay is alive)
            lastPongTime = System.currentTimeMillis();

            try {
                // Check for AUTH message first (NIP-42)
                if (text.startsWith("[\"AUTH\"")) {
                    handleAuthChallenge(webSocket, text);
                    return;
                }
                handleRelayMessage(text);
            } catch (Exception e) {
                logger.error("Error handling relay message", e);
            }
        }

        /**
         * Handle NIP-42 authentication challenge from relay.
         */
        private void handleAuthChallenge(WebSocket webSocket, String message) {
            try {
                @SuppressWarnings("unchecked")
                List<Object> json = jsonMapper.readValue(message, List.class);
                if (json.size() < 2) {
                    logger.warn("Invalid AUTH message: missing challenge");
                    return;
                }

                String challenge = (String) json.get(1);
                logger.info("Received NIP-42 auth challenge from {}", url);

                // Create auth event (kind 22242)
                long createdAt = System.currentTimeMillis() / 1000;
                Event authEvent = new Event();
                authEvent.setPubkey(keyManager.getPublicKeyHex());
                authEvent.setCreatedAt(createdAt);
                authEvent.setKind(EventKinds.AUTH);
                authEvent.setTags(Arrays.asList(
                    Arrays.asList("relay", url),
                    Arrays.asList("challenge", challenge)
                ));
                authEvent.setContent("");

                // Calculate ID and sign
                String eventId = calculateEventId(authEvent);
                authEvent.setId(eventId);

                byte[] eventIdBytes = Hex.decodeHex(eventId.toCharArray());
                String signature = keyManager.signHex(eventIdBytes);
                authEvent.setSig(signature);

                // Send AUTH response
                List<Object> authMessage = Arrays.asList("AUTH", authEvent);
                String authJson = jsonMapper.writeValueAsString(authMessage);
                webSocket.send(authJson);
                logger.info("Sent NIP-42 auth response to {}", url);

                // Re-subscribe after auth (relay may have ignored pre-auth subscriptions)
                resubscribeAfterAuth(webSocket);

            } catch (Exception e) {
                logger.error("Error handling AUTH challenge", e);
            }
        }

        private void resubscribeAfterAuth(WebSocket webSocket) {
            logger.debug("Re-subscribing after auth");
            sendAllSubscriptions(webSocket);
        }

        @Override
        public void onFailure(WebSocket webSocket, Throwable t, Response response) {
            boolean wasConnectedBefore = connected;
            connected = false;
            stopPingTimer();

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
            stopPingTimer();
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

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

    /**
     * Internal sub_id reserved for the keepalive REQ. Namespaced
     * with a {@code __nostr-sdk-} prefix so that user code calling
     * {@link #subscribe(String, Filter, NostrEventListener)} with an
     * explicit subscription id cannot collide — a user choosing the
     * literal {@code "ping"} would otherwise have their subscription
     * forcibly CLOSE/REQ'd every ping interval. The leading
     * {@code __} is a stable convention for "do not pick this name."
     */
    static final String PING_SUB_ID = "__nostr-sdk-keepalive__";

    /**
     * Filter id used by the keepalive REQ. We need a filter the relay
     * can resolve immediately (so EOSE comes back fast = relay is
     * alive), but which can NOT match any real event past EOSE (so the
     * live tail stays empty).
     *
     * <p>Earlier iterations used {@code authors:[selfPubkey]} with the
     * reasoning that "the relay would only forward our own future
     * events". That reasoning was wrong: it precisely DOES forward
     * every event the wallet publishes, including kind-31113 token
     * transfers. Some relays dedupe events across overlapping subs,
     * so the wallet's own consumer subscription would not receive its
     * echo and any flow waiting on that echo would time out.</p>
     *
     * <p>The filter {@code {"ids":["00...00"]}} asks the relay for a
     * single event whose id is exactly the all-zero hash. Real Nostr
     * event ids are SHA-256 over a canonical JSON serialization, so
     * the all-zero hash is unreachable in practice. Result: instant
     * EOSE, empty live tail.</p>
     */
    static final String KEEPALIVE_NEVER_MATCH_ID =
            "0000000000000000000000000000000000000000000000000000000000000000";

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
     * Build the keepalive REQ message ("ping") used by the per-relay
     * health-check timer.
     *
     * <p>The filter is scoped to {@code ids:[KEEPALIVE_NEVER_MATCH_ID]}
     * so it can not match any real event — neither in the initial
     * lookup nor in the post-EOSE live tail. See
     * {@link #KEEPALIVE_NEVER_MATCH_ID} for the rationale.</p>
     *
     * <p>The {@code selfPubkey} parameter is retained for API stability
     * (callers and tests still pass it) but is no longer used in the
     * filter — including it would re-introduce the live-tail leak that
     * caused self-published kind-31113 transfers to be echoed back on
     * the keepalive sub.</p>
     *
     * <p>Package-visible for testing.</p>
     */
    @SuppressWarnings("unused") // selfPubkey kept for API stability and call-site parity with TS SDK
    static String buildPingReqMessage(String selfPubkey, ObjectMapper jsonMapper)
            throws com.fasterxml.jackson.core.JsonProcessingException {
        java.util.LinkedHashMap<String, Object> pingFilter = new java.util.LinkedHashMap<>();
        pingFilter.put("ids", java.util.Collections.singletonList(KEEPALIVE_NEVER_MATCH_ID));
        pingFilter.put("limit", 1);
        return jsonMapper.writeValueAsString(java.util.Arrays.asList("REQ", PING_SUB_ID, pingFilter));
    }

    /**
     * Decide whether a relay's CLOSED reason describes a transient
     * rejection (the relay will let us retry) vs. a terminal one (the
     * relay won't accept this sub on this connection).
     *
     * <p>NIP-42: relays requiring AUTH reject pre-auth REQs with
     * {@code "auth-required:..."} (or {@code "auth-required ..."})
     * and immediately send an AUTH challenge. After we sign and the
     * AUTH succeeds, {@link RelayConnection#resubscribeAfterAuth}
     * re-issues the sub. If we treated this CLOSED as terminal
     * (marking {@code closedSubIds}), the in-flight query would
     * settle on the first CLOSED and {@code unsubscribe()} would
     * evict the sub from the global Map — by the time
     * {@code resubscribeAfterAuth} runs there would be nothing to
     * retry, and the query is permanently lost.</p>
     *
     * <p>Package-visible for testing.</p>
     */
    static boolean isTransientCloseReason(String reason) {
        if (reason == null) return false;
        // Three on-the-wire shapes: `auth-required:...` (NIP-42
        // standard with reason), `auth-required ...` (whitespace
        // separator), and bare `auth-required` (no suffix at all —
        // some relays / tests).
        return reason.equals("auth-required")
                || reason.startsWith("auth-required:")
                || reason.startsWith("auth-required ");
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

        // Mark every relay disconnected synchronously BEFORE we
        // notify subscriptions below, so any listener that consults
        // allRelaysDoneFor sees zero connected relays and settles
        // immediately. Without this, queryWithFirstSeenWins futures
        // hung until queryTimeoutMs after the user explicitly tore
        // down the client.
        for (RelayConnection connection : relayConnections.values()) {
            connection.close();
        }

        // Notify in-flight subscriptions that we're shutting down.
        // Listener-driven settlement (queryWithFirstSeenWins.onError)
        // re-checks allRelaysDoneFor; since we just closed every
        // relay it's trivially true and the future resolves now.
        notifyAllSubscriptionsError("Client disconnected");

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

        // Track per-author state in a single map so firstSeen and
        // latestEvent updates for the same pubkey are atomic. Two
        // separate maps would let pickWinner observe a pubkey in
        // firstSeen but not yet in latestEvent under multi-relay
        // concurrent dispatch, returning null prematurely.
        Map<String, AuthorState> authorState = new ConcurrentHashMap<>();

        // Pick winner from collected per-author state. Used by both
        // EOSE (clean stream end) and CLOSED (relay rejected the
        // subscription mid-stream) so the second case settles promptly
        // instead of waiting the full query timeout.
        java.util.function.Supplier<T> pickWinner = () -> {
            if (authorState.isEmpty()) {
                return null;
            }
            String winnerPubkey = null;
            long winnerFirstSeen = Long.MAX_VALUE;
            for (Map.Entry<String, AuthorState> entry : authorState.entrySet()) {
                String pubkey = entry.getKey();
                long firstSeen = entry.getValue().firstSeen;
                if (firstSeen < winnerFirstSeen
                    || (firstSeen == winnerFirstSeen && (winnerPubkey == null || pubkey.compareTo(winnerPubkey) < 0))) {
                    winnerFirstSeen = firstSeen;
                    winnerPubkey = pubkey;
                }
            }
            AuthorState winner = authorState.get(winnerPubkey);
            return winner != null && winner.latestEvent != null
                    ? extractResult.apply(winner.latestEvent)
                    : null;
        };

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

                authorState.compute(pubkey, (k, prev) -> {
                    if (prev == null) {
                        return new AuthorState(createdAt, event);
                    }
                    long firstSeen = Math.min(prev.firstSeen, createdAt);
                    Event latest = createdAt > prev.latestEvent.getCreatedAt()
                            ? event
                            : prev.latestEvent;
                    return new AuthorState(firstSeen, latest);
                });
            }

            @Override
            public void onEndOfStoredEvents(String subId) {
                // EOSE means *this relay* has finished delivering
                // stored events. In a multi-relay client we must not
                // settle yet — a slower relay may still be about to
                // deliver matching events. Settle only when every
                // connected relay has either EOSE'd OR CLOSED'd this
                // sub. Single-relay clients are unaffected: with one
                // relay, allRelaysDoneFor is trivially true.
                if (future.isDone()) return;
                if (allRelaysDoneFor(subscriptionId)) {
                    unsubscribe(subscriptionId);
                    future.complete(pickWinner.get());
                }
            }

            @Override
            public void onError(String subId, String error) {
                // Subscription error from the SDK — fired in three
                // places that all need the same "is it time to
                // settle?" check:
                //   1. Relay sent CLOSED for this sub. In a
                //      multi-relay client the same sub_id may still
                //      be alive on a healthy relay; settling on the
                //      first CLOSED would prematurely abort a query
                //      other relays could satisfy. handleClosedMessage
                //      records the rejection on the sending relay's
                //      closedSubIds before invoking us, so we can
                //      decide via allRelaysDoneFor.
                //   2. Relay disconnected mid-query (onClosed /
                //      onFailure → synthetic onError). The relay no
                //      longer counts as connected, so allRelaysDoneFor
                //      excludes it.
                //   3. Client disconnected (disconnect() → synthetic
                //      onError). All relays are torn down,
                //      allRelaysDoneFor sees zero connected and
                //      settles.
                if (future.isDone()) return;
                logger.warn("Subscription error on {}: {}", subId, error);
                if (allRelaysDoneFor(subscriptionId)) {
                    unsubscribe(subscriptionId);
                    future.complete(pickWinner.get());
                }
                // else: keep waiting for EOSE / CLOSED from remaining
                // relays or the overall query timeout.
            }
        };

        subscribe(subscriptionId, filter, listener);

        // Timeout
        CompletableFuture.delayedExecutor(queryTimeoutMs, TimeUnit.MILLISECONDS).execute(() -> {
            if (!future.isDone()) {
                logger.warn("Query timed out after {}ms", queryTimeoutMs);
                future.complete(pickWinner.get());
                unsubscribe(subscriptionId);
            }
        });

        return future;
    }

    /**
     * Best-effort notify every active subscription's listener of a
     * teardown event (relay disconnect, client disconnect). Snapshots
     * the entry set first because listeners may call
     * {@code unsubscribe()} which mutates {@code subscriptions} while
     * we iterate. Listener exceptions are swallowed — we're tearing
     * down regardless.
     *
     * <p>Used by {@link #disconnect()},
     * {@code RelayConnection.onClosed}, and
     * {@code RelayConnection.onFailure} so the three teardown paths
     * stay consistent (snapshot strategy, error message format,
     * exception handling).</p>
     */
    private void notifyAllSubscriptionsError(String reason) {
        java.util.List<Map.Entry<String, SubscriptionInfo>> inflight =
                new java.util.ArrayList<>(subscriptions.entrySet());
        for (Map.Entry<String, SubscriptionInfo> entry : inflight) {
            try {
                if (entry.getValue().listener != null) {
                    entry.getValue().listener.onError(entry.getKey(), reason);
                }
            } catch (Exception ignore) {
                // Best-effort notification.
            }
        }
    }

    /**
     * True if every currently-connected relay has finished delivering
     * for the given sub_id (either EOSE'd or CLOSED'd it). Used by
     * queryWithFirstSeenWins to coordinate multi-relay settlement.
     */
    private boolean allRelaysDoneFor(String subscriptionId) {
        java.util.List<RelayConnection> connected = new java.util.ArrayList<>();
        for (RelayConnection rc : relayConnections.values()) {
            if (rc.isConnected()) connected.add(rc);
        }
        // No connected relays at all → nothing to wait for; settle.
        if (connected.isEmpty()) return true;
        for (RelayConnection rc : connected) {
            if (!rc.eosedSubIds.contains(subscriptionId)
                    && !rc.closedSubIds.contains(subscriptionId)) {
                return false;
            }
        }
        return true;
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
     * @param subscriptionId the subscription ID to use. MUST NOT be
     *     {@link #PING_SUB_ID} (or any other id starting with the
     *     reserved {@code __nostr-sdk-} prefix) — those are used
     *     internally by the keepalive timer and would be forcibly
     *     CLOSE/REQ'd every ping interval if a caller used them.
     * @param filter the filter for events
     * @param listener the listener for received events
     * @return the subscription ID
     * @throws IllegalArgumentException if {@code subscriptionId} is
     *     reserved for SDK-internal use.
     */
    public String subscribe(String subscriptionId, Filter filter, NostrEventListener listener) {
        if (subscriptionId == null) {
            throw new IllegalArgumentException("subscriptionId must not be null");
        }
        if (subscriptionId.startsWith("__nostr-sdk-")) {
            throw new IllegalArgumentException(
                    "Subscription ID '" + subscriptionId + "' uses the reserved "
                    + "'__nostr-sdk-' prefix — pick a different id.");
        }
        subscriptions.put(subscriptionId, new SubscriptionInfo(filter, listener));

        // Wipe any stale per-relay EOSE/CLOSED markers for this sub_id
        // before issuing the REQ — otherwise a fresh subscribe with a
        // sub_id that was previously CLOSED (or was just freshly
        // EOSE'd) would be skipped or treated as "already done" on
        // those relays.
        for (RelayConnection connection : relayConnections.values()) {
            connection.closedSubIds.remove(subscriptionId);
            connection.eosedSubIds.remove(subscriptionId);
        }

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
                // Skip CLOSE on relays that already CLOSED the sub
                // themselves — no point telling the relay something
                // it told us. Drop both per-relay markers either way
                // since the sub is gone from the global map.
                if (connection.isConnected()
                        && !connection.closedSubIds.contains(subscriptionId)) {
                    connection.send(json);
                }
                connection.closedSubIds.remove(subscriptionId);
                connection.eosedSubIds.remove(subscriptionId);
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
        // `connected` is written from the OkHttp WebSocket listener
        // thread (onOpen / onClosed / onFailure) and from the
        // executor thread that runs disconnect()/scheduleReconnect();
        // it's read from listener threads via allRelaysDoneFor for
        // multi-relay query settlement. Without `volatile` a stale
        // "connected = true" read after disconnect could prevent
        // prompt query settlement on the very disconnect path the
        // settlement logic is supposed to handle.
        private volatile boolean connected = false;
        private volatile boolean wasConnected = false;
        private int reconnectAttempts = 0;
        private volatile long lastPongTime = System.currentTimeMillis();
        private volatile int unansweredPings = 0;
        private ScheduledFuture<?> pingTimer = null;
        // Sub_ids this specific relay has CLOSED for us. Used to skip
        // them in sendAllSubscriptions / post-AUTH resubscribe so we
        // don't loop on a rejected REQ. Per-relay (not global) because
        // multi-relay clients may have the same sub_id alive on a
        // healthy relay. Cleared explicitly in onOpen() (this class
        // reuses the same instance across reconnects) and in
        // resubscribeAfterAuth() so previously-rejected pre-auth REQs
        // get re-issued post-AUTH.
        private final java.util.Set<String> closedSubIds =
                java.util.Collections.newSetFromMap(new ConcurrentHashMap<>());
        // Sub_ids this specific relay has EOSE'd for us. Combined with
        // closedSubIds, lets queryWithFirstSeenWins decide when ALL
        // connected relays have finished (either streamed EOSE or
        // rejected with CLOSED), so a fast relay's EOSE doesn't
        // settle the query while a slower relay still has matching
        // events to deliver.
        private final java.util.Set<String> eosedSubIds =
                java.util.Collections.newSetFromMap(new ConcurrentHashMap<>());

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

                long timeSinceLastPong = System.currentTimeMillis() - lastPongTime;

                if (timeSinceLastPong > pingIntervalMs * 2L && unansweredPings >= 2) {
                    // No inbound message for 2x the ping interval AND we've sent at least 2 pings
                    // without any response — the connection is truly stale.
                    // The unanswered pings gate handles timer throttling (e.g., Android doze mode):
                    // on the first tick after waking, unansweredPings is 0, so we send a ping and
                    // wait. If the relay is alive it responds (resetting the counter). If dead,
                    // subsequent ticks increment the counter until it reaches the threshold.
                    logger.warn("Relay {} appears stale (no response for {}ms, {} unanswered pings), reconnecting...",
                            url, timeSinceLastPong, unansweredPings);
                    stopPingTimer();
                    try {
                        webSocket.cancel();
                    } catch (Exception e) {
                        // Ignore close errors
                    }
                    return;
                }

                // Send a subscription request as a ping (relays respond with EOSE).
                // The filter MUST be tightly scoped — an open {"limit":1}
                // filter with no kinds/authors/#p will, after EOSE, stream
                // every event the relay receives (NIP-01 live tail),
                // saturating the connection and exhausting per-connection
                // subscription slots on busy relays. Scoping by
                // authors:[self] keeps the live tail empty in practice
                // (the relay would only forward our own future events).
                // Note: OkHttp.pingInterval already runs WS frame-level
                // ping/pong; this app-level REQ exists only as a belt-and-
                // braces liveness probe and to give the relay a no-op
                // workload that's easy to reason about.
                try {
                    String closeMessage = jsonMapper.writeValueAsString(Arrays.asList("CLOSE", PING_SUB_ID));
                    webSocket.send(closeMessage);
                    String pingMessage = buildPingReqMessage(keyManager.getPublicKeyHex(), jsonMapper);
                    webSocket.send(pingMessage);
                    unansweredPings++;
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
            unansweredPings = 0;
            // Per-connection sub-slot accounting starts over on a
            // fresh socket. Unlike the TS client (which constructs a
            // new RelayConnection per connect), this Java class
            // reuses the same instance across reconnects, so we must
            // explicitly clear both closedSubIds and eosedSubIds here
            // — otherwise a sub rejected (or completed) once stays
            // permanently flagged for the life of this
            // RelayConnection.
            closedSubIds.clear();
            eosedSubIds.clear();

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
                // Skip subs this relay previously CLOSED — re-issuing
                // them just triggers the same rejection in a loop.
                // Other healthy relays still resubscribe.
                if (closedSubIds.contains(entry.getKey())) continue;
                sendSubscription(webSocket, entry.getKey(), entry.getValue().filter);
            }
        }

        @Override
        public void onMessage(WebSocket webSocket, String text) {
            // Update last pong time and reset unanswered pings on any message (relay is alive)
            lastPongTime = System.currentTimeMillis();
            unansweredPings = 0;

            try {
                // Check for AUTH message first (NIP-42)
                if (text.startsWith("[\"AUTH\"")) {
                    handleAuthChallenge(webSocket, text);
                    return;
                }
                // Hand off via the relay-aware dispatcher so CLOSED
                // frames can be attributed to this specific relay
                // rather than treated as global.
                handleRelayMessage(this, text);
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
            // Two separate per-relay markers, two separate decisions:
            //
            //  - closedSubIds: do NOT clear. handleClosedMessage
            //    already skips the auth-required transient case (via
            //    isTransientCloseReason), so anything in this set is
            //    a TERMINAL rejection (rate-limited, blocked, etc.)
            //    that AUTH does not relax. The sendAllSubscriptions
            //    guard then correctly skips terminal-rejected subs on
            //    this relay. They will be retried on the next
            //    reconnect, when onOpen creates a fresh slot count
            //    and clears these markers.
            //
            //  - eosedSubIds: clear. A relay may have EOSE'd a
            //    pre-auth sub with 0 events because the filter was
            //    unsatisfiable without auth context; post-auth the
            //    same filter might match. We must re-arm the local
            //    "still waiting" state so any in-flight
            //    queryWithFirstSeenWins doesn't see this relay as
            //    already-done from a stale marker.
            eosedSubIds.clear();
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

                // Re-trigger the all-done check on every active sub.
                // queryWithFirstSeenWins.allRelaysDoneFor only runs
                // from listener callbacks (EOSE / CLOSED via onError);
                // a socket that drops without sending either would
                // otherwise leave the query hanging until queryTimeoutMs
                // even though the disconnected relay no longer counts
                // toward "still pending" relays. Firing a synthetic
                // onError gives every active sub a chance to
                // re-evaluate now that the relay set has shrunk.
                // Include the relay URL so listeners in a multi-relay
                // client can attribute which relay dropped.
                notifyAllSubscriptionsError("Relay disconnected (" + url + "): " + reason);
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
            boolean wasConnectedBefore = connected;
            connected = false;
            stopPingTimer();
            logger.info("Relay closed: {} - {} (code: {})", url, reason, code);

            String safeReason = reason != null && !reason.isEmpty() ? reason : "Connection closed";

            // Emit disconnect event
            emitConnectionEvent("disconnect", url, safeReason);

            // Same as onFailure: synthetically notify in-flight subs
            // so multi-relay queryWithFirstSeenWins re-checks
            // allRelaysDoneFor and settles promptly when this relay
            // is no longer counted as connected. Without this the
            // query would hang until queryTimeoutMs.
            if (wasConnectedBefore) {
                notifyAllSubscriptionsError("Relay disconnected (" + url + "): " + safeReason);
            }

            // Schedule reconnect with exponential backoff if still running
            scheduleReconnect();
        }
    }

    /**
     * Backward-compat dispatcher used by tests that don't have a real
     * relay connection. Production callers go through
     * {@link #handleRelayMessage(RelayConnection, String)} so CLOSED
     * frames can be attributed to the originating relay.
     */
    private void handleRelayMessage(String message) {
        handleRelayMessage(null, message);
    }

    private void handleRelayMessage(RelayConnection relay, String message) {
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
                    handleEOSEMessage(relay, json);
                    break;
                case "NOTICE":
                    handleNoticeMessage(json);
                    break;
                case "CLOSED":
                    handleClosedMessage(relay, json);
                    break;
                default:
                    logger.debug("Unknown message type: {}", messageType);
            }
        } catch (Exception e) {
            logger.error("Error parsing relay message", e);
        }
    }

    private void handleEventMessage(List<Object> json) {
        // Defensive parity with handleClosedMessage / handleEOSEMessage:
        // a misbehaving relay sending ["EVENT", 42, ...] would otherwise
        // throw ClassCastException on (String) json.get(1) — caught
        // below, but louder and slower than an early-return.
        if (json.size() < 3 || !(json.get(1) instanceof String)) return;
        String subscriptionId = (String) json.get(1);

        SubscriptionInfo subscription = subscriptions.get(subscriptionId);
        if (subscription == null || subscription.listener == null) return;

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> eventData = (Map<String, Object>) json.get(2);
            Event event = jsonMapper.convertValue(eventData, Event.class);
            subscription.listener.onEvent(event);
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

    /**
     * Handle EOSE (End of Stored Events).
     *
     * Records the per-relay EOSE marker (mirroring closedSubIds) so
     * queryWithFirstSeenWins can decide when ALL connected relays
     * have finished — either streamed EOSE or rejected with CLOSED —
     * instead of settling off the first fast relay's EOSE while a
     * slower relay is still about to deliver matching events.
     *
     * The {@code relay} argument is nullable for the legacy
     * test-only path that drives {@code handleRelayMessage(String)}
     * without a concrete connection.
     */
    private void handleEOSEMessage(RelayConnection relay, List<Object> json) {
        if (json.size() < 2 || !(json.get(1) instanceof String)) return;
        String subscriptionId = (String) json.get(1);

        SubscriptionInfo subscription = subscriptions.get(subscriptionId);
        if (subscription == null) return;

        if (relay != null) {
            relay.eosedSubIds.add(subscriptionId);
        }

        if (subscription.listener != null) {
            subscription.listener.onEndOfStoredEvents(subscriptionId);
        }
        logger.debug("EOSE for subscription: {}", subscriptionId);
    }

    private void handleNoticeMessage(List<Object> json) {
        String notice = json.size() > 1 ? (String) json.get(1) : "";
        logger.info("Relay notice: {}", notice);
    }

    /**
     * Handle CLOSED message from relay (subscription terminated by relay).
     *
     * NIP-01 CLOSED frames are terminal for the named subscription
     * <em>on the sending relay</em>. In a multi-relay client the same
     * sub_id may still be alive on a healthy relay, so we must NOT
     * delete the global {@code subscriptions} entry here — that would
     * silently drop EVENT/EOSE frames from the still-healthy relays
     * in {@code handleEventMessage}.
     *
     * Instead we record the rejection on the sending relay's
     * {@code closedSubIds} so {@code sendAllSubscriptions} skips it on
     * this relay only. The listener is notified via {@code onError}
     * so callers (e.g. {@code queryWithFirstSeenWins}) can decide to
     * settle and explicitly call {@code unsubscribe()} if they want
     * to give up across all relays.
     *
     * <p>The {@code relay} argument is nullable: callers without a
     * concrete relay context (legacy tests) get listener notification
     * only.</p>
     *
     * <p>Per NIP-01 the message field is optional. We accept any
     * frame with at least the sub_id; missing reason becomes the
     * literal {@code "no reason provided"}.</p>
     */
    private void handleClosedMessage(RelayConnection relay, List<Object> json) {
        if (json.size() < 2) return;
        Object rawSubId = json.get(1);
        if (!(rawSubId instanceof String)) return;
        String subscriptionId = (String) rawSubId;

        // Ignore CLOSED for sub_ids we don't know about. A misbehaving
        // or malicious relay could otherwise spam us with arbitrary
        // sub_ids and grow `closedSubIds` unbounded over a long-lived
        // connection, and could pre-emptively block sub_ids we might
        // use later.
        SubscriptionInfo subscription = subscriptions.get(subscriptionId);
        if (subscription == null) return;

        String message = json.size() > 2 && json.get(2) instanceof String
                ? (String) json.get(2)
                : "no reason provided";

        // NIP-42 transient case: relays that require AUTH typically
        // reject pre-auth REQs with CLOSED("auth-required:...") and
        // then send an AUTH challenge. resubscribeAfterAuth re-issues
        // the sub, so this rejection is NOT terminal — see
        // isTransientCloseReason() for details.
        if (relay != null && !isTransientCloseReason(message)) {
            relay.closedSubIds.add(subscriptionId);
        }

        if (subscription.listener != null) {
            // Pass the relay's reason through verbatim so callers can
            // pattern-match on standard prefixes (`auth-required:`,
            // `rate-limited:`, `blocked:`, etc.) without parsing
            // through a wrapper string.
            subscription.listener.onError(subscriptionId, message);
        }
        logger.debug("CLOSED for subscription {}: {}", subscriptionId, message);
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

    /**
     * Per-author state collected during a queryWithFirstSeenWins run.
     * Combining {@code firstSeen} and {@code latestEvent} into one
     * immutable record makes updates atomic via
     * {@code ConcurrentHashMap.compute}, so {@code pickWinner} cannot
     * observe a pubkey with firstSeen set but latestEvent null.
     */
    private static class AuthorState {
        final long firstSeen;
        final Event latestEvent;

        AuthorState(long firstSeen, Event latestEvent) {
            this.firstSeen = firstSeen;
            this.latestEvent = latestEvent;
        }
    }
}

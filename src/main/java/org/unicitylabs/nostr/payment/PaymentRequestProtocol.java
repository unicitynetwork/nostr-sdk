package org.unicitylabs.nostr.payment;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * Protocol for sending payment requests and responses via Nostr.
 * Uses NIP-04 encryption for privacy.
 *
 * Flow:
 * 1. Alice wants Bob to pay her 0.001 SOL
 * 2. Alice creates a payment request with her nametag as recipient
 * 3. Alice sends the request to Bob's nametag (resolved to pubkey)
 * 4. Bob's wallet displays the request
 * 5. Bob can:
 *    a) Accept: sends the token transfer to Alice's nametag (with replyToEventId)
 *    b) Decline: sends a payment_request_response with status=DECLINED
 *    c) Ignore: request expires after deadline
 *
 * Note: The coinId precisely identifies the token type, so no separate symbol field is needed.
 */
public class PaymentRequestProtocol {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String MESSAGE_PREFIX = "payment_request:";
    private static final String RESPONSE_PREFIX = "payment_request_response:";

    /** Default deadline duration: 5 minutes in milliseconds */
    public static final long DEFAULT_DEADLINE_MS = 5 * 60 * 1000;

    /**
     * Payment request response status.
     */
    public enum ResponseStatus {
        /** Payment request was declined by the recipient */
        DECLINED,
        /** Payment request expired (deadline passed) */
        EXPIRED
    }

    /**
     * Payment request data.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PaymentRequest {
        /** Amount in smallest units (e.g., lamports for SOL) - uses BigInteger to handle large values */
        @JsonProperty("amount")
        private BigInteger amount;

        /** Coin/token type ID - precisely identifies the token type */
        @JsonProperty("coinId")
        private String coinId;

        /** Optional message describing the payment */
        @JsonProperty("message")
        private String message;

        /** Nametag of the payment recipient (who is requesting payment) */
        @JsonProperty("recipientNametag")
        private String recipientNametag;

        /** Request ID for tracking (auto-generated if not provided) */
        @JsonProperty("requestId")
        private String requestId;

        /** Deadline timestamp in milliseconds (Unix epoch). Null means no deadline. */
        @JsonProperty("deadline")
        private Long deadline;

        public PaymentRequest() {}

        public PaymentRequest(BigInteger amount, String coinId, String message, String recipientNametag) {
            this(amount, coinId, message, recipientNametag, System.currentTimeMillis() + DEFAULT_DEADLINE_MS);
        }

        public PaymentRequest(BigInteger amount, String coinId, String message, String recipientNametag, Long deadline) {
            this.amount = amount;
            this.coinId = coinId;
            this.message = message;
            this.recipientNametag = recipientNametag;
            this.requestId = UUID.randomUUID().toString().substring(0, 8);
            this.deadline = deadline;
        }

        /**
         * Convenience constructor accepting long amount (for small values).
         */
        public PaymentRequest(long amount, String coinId, String message, String recipientNametag) {
            this(BigInteger.valueOf(amount), coinId, message, recipientNametag);
        }

        /**
         * Convenience constructor accepting long amount and deadline.
         */
        public PaymentRequest(long amount, String coinId, String message, String recipientNametag, Long deadline) {
            this(BigInteger.valueOf(amount), coinId, message, recipientNametag, deadline);
        }

        // Getters and setters
        public BigInteger getAmount() { return amount; }
        public void setAmount(BigInteger amount) { this.amount = amount; }

        /**
         * Convenience setter for long values.
         */
        public void setAmount(long amount) { this.amount = BigInteger.valueOf(amount); }

        public String getCoinId() { return coinId; }
        public void setCoinId(String coinId) { this.coinId = coinId; }

        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }

        public String getRecipientNametag() { return recipientNametag; }
        public void setRecipientNametag(String recipientNametag) { this.recipientNametag = recipientNametag; }

        public String getRequestId() { return requestId; }
        public void setRequestId(String requestId) { this.requestId = requestId; }

        public Long getDeadline() { return deadline; }
        public void setDeadline(Long deadline) { this.deadline = deadline; }

        /**
         * Check if the payment request has expired.
         * @return true if the request has a deadline and it has passed
         */
        public boolean isExpired() {
            return deadline != null && System.currentTimeMillis() > deadline;
        }

        /**
         * Get remaining time until deadline in milliseconds.
         * @return remaining time in milliseconds, 0 if expired, null if no deadline
         */
        public Long getRemainingTimeMs() {
            if (deadline == null) return null;
            long remaining = deadline - System.currentTimeMillis();
            return remaining > 0 ? remaining : 0L;
        }

        @Override
        public String toString() {
            return "PaymentRequest{" +
                    "amount=" + amount +
                    ", coinId='" + coinId + '\'' +
                    ", message='" + message + '\'' +
                    ", recipientNametag='" + recipientNametag + '\'' +
                    ", requestId='" + requestId + '\'' +
                    ", deadline=" + deadline +
                    '}';
        }
    }

    /**
     * Payment request response data (for decline/expiration notifications).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PaymentRequestResponse {
        /** The original request ID being responded to */
        @JsonProperty("requestId")
        private String requestId;

        /** The original event ID being responded to */
        @JsonProperty("originalEventId")
        private String originalEventId;

        /** Response status (DECLINED, EXPIRED) */
        @JsonProperty("status")
        private ResponseStatus status;

        /** Optional reason for decline/expiration */
        @JsonProperty("reason")
        private String reason;

        public PaymentRequestResponse() {}

        public PaymentRequestResponse(String requestId, String originalEventId, ResponseStatus status, String reason) {
            this.requestId = requestId;
            this.originalEventId = originalEventId;
            this.status = status;
            this.reason = reason;
        }

        public String getRequestId() { return requestId; }
        public void setRequestId(String requestId) { this.requestId = requestId; }

        public String getOriginalEventId() { return originalEventId; }
        public void setOriginalEventId(String originalEventId) { this.originalEventId = originalEventId; }

        public ResponseStatus getStatus() { return status; }
        public void setStatus(ResponseStatus status) { this.status = status; }

        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }

        @Override
        public String toString() {
            return "PaymentRequestResponse{" +
                    "requestId='" + requestId + '\'' +
                    ", originalEventId='" + originalEventId + '\'' +
                    ", status=" + status +
                    ", reason='" + reason + '\'' +
                    '}';
        }
    }

    /**
     * Create a payment request event.
     *
     * @param keyManager Key manager for signing and encryption
     * @param targetPubkeyHex Target's public key (who should pay)
     * @param request Payment request details
     * @return Signed payment request event
     * @throws Exception if event creation fails
     */
    public static Event createPaymentRequestEvent(NostrKeyManager keyManager, String targetPubkeyHex,
                                                   PaymentRequest request) throws Exception {
        long createdAt = System.currentTimeMillis() / 1000;

        // Serialize request to JSON
        String requestJson = JSON.writeValueAsString(request);

        // Create content with prefix
        String content = MESSAGE_PREFIX + requestJson;

        // Encrypt with NIP-04
        String encryptedContent = keyManager.encryptHex(content, targetPubkeyHex);

        // Create tags
        List<List<String>> tags = new ArrayList<>();
        tags.add(Arrays.asList("p", targetPubkeyHex));  // Target pubkey (who should pay)
        tags.add(Arrays.asList("type", "payment_request"));
        tags.add(Arrays.asList("amount", request.getAmount().toString()));
        if (request.getRecipientNametag() != null) {
            tags.add(Arrays.asList("recipient", request.getRecipientNametag()));
        }

        // Create event
        Event event = new Event();
        event.setPubkey(keyManager.getPublicKeyHex());
        event.setCreatedAt(createdAt);
        event.setKind(EventKinds.PAYMENT_REQUEST);
        event.setTags(tags);
        event.setContent(encryptedContent);

        // Calculate event ID
        String eventId = calculateEventId(event);
        event.setId(eventId);

        // Sign event
        byte[] eventIdBytes = Hex.decodeHex(eventId.toCharArray());
        String signature = keyManager.signHex(eventIdBytes);
        event.setSig(signature);

        return event;
    }

    /**
     * Parse and decrypt a payment request event.
     *
     * @param event Payment request event
     * @param keyManager Recipient's key manager for decryption
     * @return Parsed payment request
     * @throws Exception if parsing fails
     */
    public static PaymentRequest parsePaymentRequest(Event event, NostrKeyManager keyManager) throws Exception {
        if (event.getKind() != EventKinds.PAYMENT_REQUEST) {
            throw new IllegalArgumentException("Event is not a payment request (kind " + event.getKind() + ")");
        }

        // Get sender's pubkey
        String senderPubkeyHex = event.getPubkey();

        // Decrypt content
        String decryptedContent = keyManager.decryptHex(event.getContent(), senderPubkeyHex);

        // Validate prefix
        if (!decryptedContent.startsWith(MESSAGE_PREFIX)) {
            throw new IllegalArgumentException("Invalid payment request format: missing prefix");
        }

        // Extract and parse JSON
        String requestJson = decryptedContent.substring(MESSAGE_PREFIX.length());
        return JSON.readValue(requestJson, PaymentRequest.class);
    }

    /**
     * Get amount from payment request event tags (unencrypted metadata).
     *
     * @param event Payment request event
     * @return Amount or null if not present
     */
    public static BigInteger getAmount(Event event) {
        String amountStr = event.getTagValue("amount");
        if (amountStr != null) {
            try {
                return new BigInteger(amountStr);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Get recipient nametag from payment request event tags.
     *
     * @param event Payment request event
     * @return Recipient nametag or null if not present
     */
    public static String getRecipientNametag(Event event) {
        return event.getTagValue("recipient");
    }

    /**
     * Create a payment request response event (for decline/expiration).
     *
     * @param keyManager Key manager for signing and encryption
     * @param targetPubkeyHex Target's public key (original request sender)
     * @param response Payment request response
     * @return Signed payment request response event
     * @throws Exception if event creation fails
     */
    public static Event createPaymentRequestResponseEvent(NostrKeyManager keyManager, String targetPubkeyHex,
                                                          PaymentRequestResponse response) throws Exception {
        long createdAt = System.currentTimeMillis() / 1000;

        // Serialize response to JSON
        String responseJson = JSON.writeValueAsString(response);

        // Create content with prefix
        String content = RESPONSE_PREFIX + responseJson;

        // Encrypt with NIP-04
        String encryptedContent = keyManager.encryptHex(content, targetPubkeyHex);

        // Create tags
        List<List<String>> tags = new ArrayList<>();
        tags.add(Arrays.asList("p", targetPubkeyHex));  // Target pubkey (original requester)
        tags.add(Arrays.asList("type", "payment_request_response"));
        tags.add(Arrays.asList("status", response.getStatus().name()));
        // Reference the original event for correlation
        if (response.getOriginalEventId() != null && !response.getOriginalEventId().isEmpty()) {
            tags.add(Arrays.asList("e", response.getOriginalEventId(), "", "reply"));
        }

        // Create event
        Event event = new Event();
        event.setPubkey(keyManager.getPublicKeyHex());
        event.setCreatedAt(createdAt);
        event.setKind(EventKinds.PAYMENT_REQUEST_RESPONSE);
        event.setTags(tags);
        event.setContent(encryptedContent);

        // Calculate event ID
        String eventId = calculateEventId(event);
        event.setId(eventId);

        // Sign event
        byte[] eventIdBytes = Hex.decodeHex(eventId.toCharArray());
        String signature = keyManager.signHex(eventIdBytes);
        event.setSig(signature);

        return event;
    }

    /**
     * Parse and decrypt a payment request response event.
     *
     * @param event Payment request response event
     * @param keyManager Recipient's key manager for decryption
     * @return Parsed payment request response
     * @throws Exception if parsing fails
     */
    public static PaymentRequestResponse parsePaymentRequestResponse(Event event, NostrKeyManager keyManager) throws Exception {
        if (event.getKind() != EventKinds.PAYMENT_REQUEST_RESPONSE) {
            throw new IllegalArgumentException("Event is not a payment request response (kind " + event.getKind() + ")");
        }

        // Get sender's pubkey
        String senderPubkeyHex = event.getPubkey();

        // Decrypt content
        String decryptedContent = keyManager.decryptHex(event.getContent(), senderPubkeyHex);

        // Validate prefix
        if (!decryptedContent.startsWith(RESPONSE_PREFIX)) {
            throw new IllegalArgumentException("Invalid payment request response format: missing prefix");
        }

        // Extract and parse JSON
        String responseJson = decryptedContent.substring(RESPONSE_PREFIX.length());
        return JSON.readValue(responseJson, PaymentRequestResponse.class);
    }

    /**
     * Get the response status from payment request response event tags (unencrypted).
     *
     * @param event Payment request response event
     * @return Status string or null if not present
     */
    public static String getResponseStatus(Event event) {
        return event.getTagValue("status");
    }

    /**
     * Get the referenced original event ID from the response event.
     *
     * @param event Payment request response event
     * @return Original event ID or null if not present
     */
    public static String getOriginalEventId(Event event) {
        return event.getTagValue("e");
    }

    /**
     * Calculate Nostr event ID (SHA-256 of canonical JSON).
     */
    private static String calculateEventId(Event event) throws Exception {
        List<Object> eventData = Arrays.asList(
            0,
            event.getPubkey(),
            event.getCreatedAt(),
            event.getKind(),
            event.getTags(),
            event.getContent()
        );

        String eventJson = JSON.writeValueAsString(eventData);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(eventJson.getBytes(StandardCharsets.UTF_8));

        return new String(Hex.encodeHex(hashBytes));
    }

    private PaymentRequestProtocol() {
        // Utility class
    }
}

package org.unicitylabs.nostr.payment;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * Protocol for sending payment requests via Nostr.
 * Uses NIP-04 encryption for privacy.
 *
 * Flow:
 * 1. Alice wants Bob to pay her 0.001 SOL
 * 2. Alice creates a payment request with her nametag as recipient
 * 3. Alice sends the request to Bob's nametag (resolved to pubkey)
 * 4. Bob's wallet displays the request
 * 5. Bob accepts and sends the token transfer to Alice's nametag
 *
 * Note: The coinId precisely identifies the token type, so no separate symbol field is needed.
 */
public class PaymentRequestProtocol {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String MESSAGE_PREFIX = "payment_request:";

    /**
     * Payment request data.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PaymentRequest {
        /** Amount in smallest units (e.g., lamports for SOL) */
        @JsonProperty("amount")
        private long amount;

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

        public PaymentRequest() {}

        public PaymentRequest(long amount, String coinId, String message, String recipientNametag) {
            this.amount = amount;
            this.coinId = coinId;
            this.message = message;
            this.recipientNametag = recipientNametag;
            this.requestId = UUID.randomUUID().toString().substring(0, 8);
        }

        // Getters and setters
        public long getAmount() { return amount; }
        public void setAmount(long amount) { this.amount = amount; }

        public String getCoinId() { return coinId; }
        public void setCoinId(String coinId) { this.coinId = coinId; }

        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }

        public String getRecipientNametag() { return recipientNametag; }
        public void setRecipientNametag(String recipientNametag) { this.recipientNametag = recipientNametag; }

        public String getRequestId() { return requestId; }
        public void setRequestId(String requestId) { this.requestId = requestId; }

        @Override
        public String toString() {
            return "PaymentRequest{" +
                    "amount=" + amount +
                    ", coinId='" + coinId + '\'' +
                    ", message='" + message + '\'' +
                    ", recipientNametag='" + recipientNametag + '\'' +
                    ", requestId='" + requestId + '\'' +
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
        tags.add(Arrays.asList("amount", String.valueOf(request.getAmount())));
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
    public static Long getAmount(Event event) {
        String amountStr = event.getTagValue("amount");
        if (amountStr != null) {
            try {
                return Long.parseLong(amountStr);
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

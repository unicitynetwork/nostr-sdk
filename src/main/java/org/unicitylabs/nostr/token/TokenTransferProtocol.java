package org.unicitylabs.nostr.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * Protocol for transferring Unicity tokens via Nostr.
 * Uses NIP-04 encryption with GZIP compression for large token JSONs.
 */
public class TokenTransferProtocol {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String MESSAGE_PREFIX = "token_transfer:";

    /**
     * Create a token transfer event.
     * Encrypts the token JSON with NIP-04 (with compression for large payloads).
     *
     * @param keyManager Sender's NostrKeyManager
     * @param recipientPubkeyHex Recipient's public key (hex)
     * @param tokenJson Unicity SDK token JSON
     * @param amount Optional amount for metadata
     * @param symbol Optional symbol for metadata
     * @return Signed token transfer event
     */
    public static Event createTokenTransferEvent(NostrKeyManager keyManager, String recipientPubkeyHex,
                                                String tokenJson, Long amount, String symbol) throws Exception {
        long createdAt = System.currentTimeMillis() / 1000;

        // Create content: "token_transfer:{tokenJson}"
        String content = MESSAGE_PREFIX + tokenJson;

        // Encrypt with NIP-04 (automatically compresses if large)
        String encryptedContent = keyManager.encryptHex(content, recipientPubkeyHex);

        // Create tags
        List<List<String>> tags = new ArrayList<>();
        tags.add(Arrays.asList("p", recipientPubkeyHex));  // Recipient pubkey
        tags.add(Arrays.asList("type", "token_transfer"));  // Event type

        // Add optional amount/symbol tags if provided
        if (amount != null && symbol != null) {
            tags.add(Arrays.asList("amount", amount.toString()));
            tags.add(Arrays.asList("symbol", symbol));
        }

        // Create event
        Event event = new Event();
        event.setPubkey(keyManager.getPublicKeyHex());
        event.setCreatedAt(createdAt);
        event.setKind(EventKinds.TOKEN_TRANSFER);
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
     * Create a token transfer event without amount/symbol metadata.
     */
    public static Event createTokenTransferEvent(NostrKeyManager keyManager, String recipientPubkeyHex,
                                                String tokenJson) throws Exception {
        return createTokenTransferEvent(keyManager, recipientPubkeyHex, tokenJson, null, null);
    }

    /**
     * Parse and decrypt a token transfer event.
     * Returns the token JSON string.
     *
     * @param event Token transfer event
     * @param keyManager Recipient's NostrKeyManager
     * @return Token JSON string
     */
    public static String parseTokenTransfer(Event event, NostrKeyManager keyManager) throws Exception {
        if (event.getKind() != EventKinds.TOKEN_TRANSFER) {
            throw new IllegalArgumentException("Event is not a token transfer (kind " + event.getKind() + ")");
        }

        // Get sender's pubkey
        String senderPubkeyHex = event.getPubkey();

        // Decrypt content (automatically decompresses if needed)
        String decryptedContent;
        try {
            // Try NIP-04 encryption (new format)
            decryptedContent = keyManager.decryptHex(event.getContent(), senderPubkeyHex);
        } catch (Exception e) {
            // Fallback to legacy hex encoding (for backward compatibility)
            try {
                byte[] hexDecoded = Hex.decodeHex(event.getContent().toCharArray());
                decryptedContent = new String(hexDecoded, StandardCharsets.UTF_8);
            } catch (DecoderException hexError) {
                throw new Exception("Failed to decrypt token transfer: NIP-04 failed and hex fallback failed", e);
            }
        }

        // Validate prefix
        if (!decryptedContent.startsWith(MESSAGE_PREFIX)) {
            throw new IllegalArgumentException("Invalid token transfer format: missing prefix");
        }

        // Extract token JSON
        return decryptedContent.substring(MESSAGE_PREFIX.length());
    }

    /**
     * Get amount metadata from token transfer event.
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
     * Get symbol metadata from token transfer event.
     */
    public static String getSymbol(Event event) {
        return event.getTagValue("symbol");
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

    private TokenTransferProtocol() {
        // Utility class
    }
}

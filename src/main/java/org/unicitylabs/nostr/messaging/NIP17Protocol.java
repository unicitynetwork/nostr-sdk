package org.unicitylabs.nostr.messaging;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.unicitylabs.nostr.crypto.NIP44Encryption;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.crypto.SchnorrSigner;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

/**
 * NIP-17 Private Direct Messages Protocol.
 * Implements gift-wrapping for sender anonymity using NIP-44 encryption.
 *
 * Message flow:
 * 1. Create Rumor (kind 14, unsigned) with actual message content
 * 2. Create Seal (kind 13, signed by sender) encrypting the rumor
 * 3. Create Gift Wrap (kind 1059, signed by random ephemeral key) encrypting the seal
 *
 * Only the recipient can decrypt and verify the true sender.
 */
public class NIP17Protocol {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    // Randomization window for timestamps (+/- 2 days in seconds)
    private static final long TIMESTAMP_RANDOMIZATION = 2 * 24 * 60 * 60;

    /**
     * Create a gift-wrapped private message.
     *
     * @param senderKeys Sender's key manager
     * @param recipientPubkeyHex Recipient's public key (hex)
     * @param content Message content
     * @return Gift-wrapped event (kind 1059)
     * @throws Exception if creation fails
     */
    public static Event createGiftWrap(NostrKeyManager senderKeys, String recipientPubkeyHex,
                                        String content) throws Exception {
        return createGiftWrap(senderKeys, recipientPubkeyHex, content, null);
    }

    /**
     * Create a gift-wrapped private message with optional reply reference.
     *
     * @param senderKeys Sender's key manager
     * @param recipientPubkeyHex Recipient's public key (hex)
     * @param content Message content
     * @param replyToEventId Optional event ID this message is replying to
     * @return Gift-wrapped event (kind 1059)
     * @throws Exception if creation fails
     */
    public static Event createGiftWrap(NostrKeyManager senderKeys, String recipientPubkeyHex,
                                        String content, String replyToEventId) throws Exception {
        return createGiftWrap(senderKeys, recipientPubkeyHex, content, replyToEventId, null);
    }

    /**
     * Create a gift-wrapped private message with sender nametag.
     *
     * @param senderKeys Sender's key manager
     * @param recipientPubkeyHex Recipient's public key (hex)
     * @param content Message content
     * @param replyToEventId Optional event ID this message is replying to
     * @param senderNametag Optional sender's nametag for identification
     * @return Gift-wrapped event (kind 1059)
     * @throws Exception if creation fails
     */
    public static Event createGiftWrap(NostrKeyManager senderKeys, String recipientPubkeyHex,
                                        String content, String replyToEventId,
                                        String senderNametag) throws Exception {
        // 1. Create Rumor (kind 14, unsigned)
        Rumor rumor = createRumor(senderKeys.getPublicKeyHex(), recipientPubkeyHex,
                content, EventKinds.CHAT_MESSAGE, replyToEventId, senderNametag);

        // 2. Create Seal (kind 13, signed by sender, encrypts rumor)
        Event seal = createSeal(senderKeys, recipientPubkeyHex, rumor);

        // 3. Create Gift Wrap (kind 1059, signed by ephemeral key, encrypts seal)
        return wrapSeal(seal, recipientPubkeyHex);
    }

    /**
     * Create a gift-wrapped read receipt.
     *
     * @param senderKeys Sender's key manager
     * @param recipientPubkeyHex Recipient (original sender) public key
     * @param messageEventId Event ID of the message being acknowledged
     * @return Gift-wrapped read receipt event
     * @throws Exception if creation fails
     */
    public static Event createReadReceipt(NostrKeyManager senderKeys, String recipientPubkeyHex,
                                           String messageEventId) throws Exception {
        // Create rumor with kind 15 (read receipt)
        List<List<String>> tags = new ArrayList<>();
        tags.add(Arrays.asList("p", recipientPubkeyHex));
        tags.add(Arrays.asList("e", messageEventId));

        // Use actual timestamp for rumor (privacy via outer layers)
        long actualTimestamp = System.currentTimeMillis() / 1000;

        Rumor rumor = new Rumor(
                senderKeys.getPublicKeyHex(),
                actualTimestamp,
                EventKinds.READ_RECEIPT,
                tags,
                ""  // Read receipts have empty content
        );

        Event seal = createSeal(senderKeys, recipientPubkeyHex, rumor);
        return wrapSeal(seal, recipientPubkeyHex);
    }

    /**
     * Unwrap a gift-wrapped message.
     *
     * @param giftWrap Gift wrap event (kind 1059)
     * @param recipientKeys Recipient's key manager
     * @return Parsed private message
     * @throws Exception if unwrapping fails
     */
    public static PrivateMessage unwrap(Event giftWrap, NostrKeyManager recipientKeys) throws Exception {
        if (giftWrap.getKind() != EventKinds.GIFT_WRAP) {
            throw new IllegalArgumentException("Event is not a gift wrap (kind " + giftWrap.getKind() + ")");
        }

        // Get ephemeral sender's pubkey from gift wrap
        String ephemeralPubkey = giftWrap.getPubkey();
        byte[] ephemeralPubkeyBytes = Hex.decodeHex(ephemeralPubkey.toCharArray());

        // Decrypt seal from gift wrap content
        String sealJson = NIP44Encryption.decrypt(
                giftWrap.getContent(),
                recipientKeys.getPrivateKey(),
                ephemeralPubkeyBytes
        );

        Event seal = JSON.readValue(sealJson, Event.class);

        if (seal.getKind() != EventKinds.SEAL) {
            throw new IllegalArgumentException("Inner event is not a seal (kind " + seal.getKind() + ")");
        }

        // Verify seal signature
        String sealPubkey = seal.getPubkey();
        byte[] sealIdBytes = Hex.decodeHex(seal.getId().toCharArray());
        byte[] sigBytes = Hex.decodeHex(seal.getSig().toCharArray());
        byte[] pubkeyBytes = Hex.decodeHex(sealPubkey.toCharArray());

        if (!SchnorrSigner.verify(sigBytes, sealIdBytes, pubkeyBytes)) {
            throw new SecurityException("Seal signature verification failed");
        }

        // Decrypt rumor from seal content
        String rumorJson = NIP44Encryption.decrypt(
                seal.getContent(),
                recipientKeys.getPrivateKey(),
                pubkeyBytes
        );

        Rumor rumor = Rumor.fromJson(rumorJson);

        // Extract reply-to event ID if present
        String replyToEventId = rumor.getTagValue("e");

        // Extract sender's nametag if present
        String senderNametag = rumor.getTagValue("nametag");

        return PrivateMessage.builder()
                .eventId(giftWrap.getId())
                .senderPubkey(sealPubkey)
                .senderNametag(senderNametag)
                .recipientPubkey(recipientKeys.getPublicKeyHex())
                .content(rumor.getContent())
                .timestamp(rumor.getCreatedAt())
                .kind(rumor.getKind())
                .replyToEventId(replyToEventId)
                .build();
    }

    // ========== Helper Methods ==========

    /**
     * Create an unsigned rumor (kind 14 or 15).
     */
    private static Rumor createRumor(String senderPubkey, String recipientPubkey,
                                      String content, int kind, String replyToEventId) {
        return createRumor(senderPubkey, recipientPubkey, content, kind, replyToEventId, null);
    }

    /**
     * Create an unsigned rumor with optional sender nametag.
     * Note: Rumor uses actual timestamp for correct message ordering.
     * Only seal and gift wrap use randomized timestamps for privacy.
     */
    private static Rumor createRumor(String senderPubkey, String recipientPubkey,
                                      String content, int kind, String replyToEventId,
                                      String senderNametag) {
        List<List<String>> tags = new ArrayList<>();
        tags.add(Arrays.asList("p", recipientPubkey));

        if (replyToEventId != null && !replyToEventId.isEmpty()) {
            tags.add(Arrays.asList("e", replyToEventId, "", "reply"));
        }

        // Add sender's nametag for identification (allows receiver to display user-friendly name)
        if (senderNametag != null && !senderNametag.isEmpty()) {
            tags.add(Arrays.asList("nametag", senderNametag));
        }

        // Use actual timestamp for rumor (inner message) - needed for correct ordering
        // Privacy is provided by randomized timestamps on seal and gift wrap layers
        long actualTimestamp = System.currentTimeMillis() / 1000;

        return new Rumor(
                senderPubkey,
                actualTimestamp,
                kind,
                tags,
                content
        );
    }

    /**
     * Create a seal (kind 13) that encrypts a rumor.
     */
    private static Event createSeal(NostrKeyManager senderKeys, String recipientPubkeyHex,
                                     Rumor rumor) throws Exception {
        String rumorJson = rumor.toJson();

        // Encrypt rumor with NIP-44
        byte[] recipientPubkey = Hex.decodeHex(recipientPubkeyHex.toCharArray());
        String encryptedRumor = NIP44Encryption.encrypt(rumorJson, senderKeys.getPrivateKey(), recipientPubkey);

        // Create seal event
        Event seal = new Event();
        seal.setPubkey(senderKeys.getPublicKeyHex());
        seal.setCreatedAt(randomizeTimestamp());
        seal.setKind(EventKinds.SEAL);
        seal.setTags(new ArrayList<>());  // Seals have no tags
        seal.setContent(encryptedRumor);

        // Calculate ID and sign
        String sealId = calculateEventId(seal);
        seal.setId(sealId);

        byte[] sealIdBytes = Hex.decodeHex(sealId.toCharArray());
        String signature = senderKeys.signHex(sealIdBytes);
        seal.setSig(signature);

        return seal;
    }

    /**
     * Wrap a seal in a gift wrap (kind 1059) using an ephemeral key.
     */
    private static Event wrapSeal(Event seal, String recipientPubkeyHex) throws Exception {
        // Generate ephemeral key for the gift wrap
        NostrKeyManager ephemeralKeys = NostrKeyManager.generate();

        String sealJson = JSON.writeValueAsString(seal);

        // Encrypt seal with NIP-44 using ephemeral key
        byte[] recipientPubkey = Hex.decodeHex(recipientPubkeyHex.toCharArray());
        String encryptedSeal = NIP44Encryption.encrypt(sealJson, ephemeralKeys.getPrivateKey(), recipientPubkey);

        // Create gift wrap tags
        List<List<String>> tags = new ArrayList<>();
        tags.add(Arrays.asList("p", recipientPubkeyHex));

        // Create gift wrap event
        Event giftWrap = new Event();
        giftWrap.setPubkey(ephemeralKeys.getPublicKeyHex());
        giftWrap.setCreatedAt(randomizeTimestamp());
        giftWrap.setKind(EventKinds.GIFT_WRAP);
        giftWrap.setTags(tags);
        giftWrap.setContent(encryptedSeal);

        // Calculate ID and sign with ephemeral key
        String giftWrapId = calculateEventId(giftWrap);
        giftWrap.setId(giftWrapId);

        byte[] giftWrapIdBytes = Hex.decodeHex(giftWrapId.toCharArray());
        String signature = ephemeralKeys.signHex(giftWrapIdBytes);
        giftWrap.setSig(signature);

        // Clear ephemeral key from memory
        ephemeralKeys.clear();

        return giftWrap;
    }

    /**
     * Generate a randomized timestamp for privacy (+/- 2 days).
     */
    private static long randomizeTimestamp() {
        long now = System.currentTimeMillis() / 1000;
        // Range is 4 days in seconds (345600), fits in int
        // Using nextInt(bound) guarantees non-negative result in [0, bound)
        int range = (int) (2 * TIMESTAMP_RANDOMIZATION);
        long randomOffset = RANDOM.nextInt(range) - TIMESTAMP_RANDOMIZATION;
        return now + randomOffset;
    }

    /**
     * Calculate event ID as SHA-256 of serialized event data.
     */
    private static String calculateEventId(Event event) throws Exception {
        // Serialize as: [0, pubkey, created_at, kind, tags, content]
        StringBuilder sb = new StringBuilder();
        sb.append("[0,\"");
        sb.append(event.getPubkey());
        sb.append("\",");
        sb.append(event.getCreatedAt());
        sb.append(",");
        sb.append(event.getKind());
        sb.append(",");
        sb.append(JSON.writeValueAsString(event.getTags()));
        sb.append(",");
        sb.append(JSON.writeValueAsString(event.getContent()));
        sb.append("]");

        byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(bytes);

        return new String(Hex.encodeHex(hash));
    }

    private NIP17Protocol() {
        // Utility class
    }
}

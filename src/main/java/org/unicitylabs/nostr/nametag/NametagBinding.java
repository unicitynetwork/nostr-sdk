package org.unicitylabs.nostr.nametag;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;
import org.unicitylabs.nostr.protocol.Filter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * Manages Unicity nametag → Nostr pubkey bindings using replaceable events.
 * One-directional: nametag resolves to pubkey (not reverse).
 * Uses hashed nametags for privacy.
 */
public class NametagBinding {

    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Create a nametag binding event.
     * This is a parameterized replaceable event (kind 30078) that maps a Nostr pubkey to a Unicity nametag.
     *
     * @param keyManager NostrKeyManager to sign the event
     * @param nametagId Nametag identifier (e.g., "alice@unicity" or phone number)
     * @param unicityAddress Unicity blockchain address
     * @param defaultCountry Default country for phone normalization (e.g., "US")
     * @return Signed binding event
     */
    public static Event createBindingEvent(NostrKeyManager keyManager, String nametagId,
                                          String unicityAddress, String defaultCountry) throws Exception {
        long createdAt = System.currentTimeMillis() / 1000;

        // Hash the nametag for privacy
        String hashedNametag = NametagUtils.hashNametag(nametagId, defaultCountry);

        // Create tags for the replaceable event
        List<List<String>> tags = new ArrayList<>();
        tags.add(Arrays.asList("d", hashedNametag));  // Unique per nametag - allows multiple bindings
        tags.add(Arrays.asList("nametag", hashedNametag));  // Store HASHED nametag for privacy
        tags.add(Arrays.asList("t", hashedNametag));  // Use 't' tag which is indexed by relay
        tags.add(Arrays.asList("address", unicityAddress));  // Store Unicity address

        // Create content with binding information
        Map<String, Object> contentData = new LinkedHashMap<>();
        contentData.put("nametag_hash", hashedNametag);
        contentData.put("address", unicityAddress);
        contentData.put("verified", System.currentTimeMillis());
        String content = JSON.writeValueAsString(contentData);

        // Create event for signing
        Event event = new Event();
        event.setPubkey(keyManager.getPublicKeyHex());
        event.setCreatedAt(createdAt);
        event.setKind(EventKinds.APP_DATA);
        event.setTags(tags);
        event.setContent(content);

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
     * Create a nametag binding event with default country "US".
     */
    public static Event createBindingEvent(NostrKeyManager keyManager, String nametagId,
                                          String unicityAddress) throws Exception {
        return createBindingEvent(keyManager, nametagId, unicityAddress, "US");
    }

    /**
     * Create a filter to find Nostr pubkey by nametag.
     * This is the primary query direction: nametag → pubkey.
     *
     * @param nametagId Nametag identifier
     * @param defaultCountry Default country for phone normalization
     * @return Filter for querying the binding
     */
    public static Filter createNametagToPubkeyFilter(String nametagId, String defaultCountry) {
        String hashedNametag = NametagUtils.hashNametag(nametagId, defaultCountry);

        return Filter.builder()
            .kinds(EventKinds.APP_DATA)
            .tTags(hashedNametag)  // Query by HASHED nametag using indexed 't' tag
            .limit(1)
            .build();
    }

    /**
     * Create a filter to find Nostr pubkey by nametag (default country "US").
     */
    public static Filter createNametagToPubkeyFilter(String nametagId) {
        return createNametagToPubkeyFilter(nametagId, "US");
    }

    /**
     * Create a filter to find nametags by Nostr pubkey.
     * Returns all nametags bound to a given pubkey.
     *
     * @param nostrPubkey Nostr public key (hex)
     * @return Filter for querying bindings by pubkey
     */
    public static Filter createPubkeyToNametagFilter(String nostrPubkey) {
        return Filter.builder()
            .kinds(EventKinds.APP_DATA)
            .authors(nostrPubkey)
            .limit(10)  // Allow multiple nametags per pubkey
            .build();
    }

    /**
     * Parse nametag hash from a binding event.
     *
     * @param event Binding event
     * @return Nametag hash or null if not found
     */
    public static String parseNametagHashFromEvent(Event event) {
        if (event == null || event.getKind() != EventKinds.APP_DATA) {
            return null;
        }

        // Look for nametag in tags
        for (List<String> tag : event.getTags()) {
            if (tag.size() >= 2 && "nametag".equals(tag.get(0))) {
                return tag.get(1);
            }
        }

        // Fallback to parsing from content
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> contentData = JSON.readValue(event.getContent(), Map.class);
            return (String) contentData.get("nametag_hash");
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Parse Unicity address from a binding event.
     *
     * @param event Binding event
     * @return Unicity address or null if not found
     */
    public static String parseAddressFromEvent(Event event) {
        if (event == null || event.getKind() != EventKinds.APP_DATA) {
            return null;
        }

        // Look for address in tags
        for (List<String> tag : event.getTags()) {
            if (tag.size() >= 2 && "address".equals(tag.get(0))) {
                return tag.get(1);
            }
        }

        // Fallback to parsing from content
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> contentData = JSON.readValue(event.getContent(), Map.class);
            return (String) contentData.get("address");
        } catch (Exception e) {
            return null;
        }
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

    private NametagBinding() {
        // Utility class
    }
}

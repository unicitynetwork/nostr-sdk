package org.unicitylabs.nostr.nametag;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;
import org.unicitylabs.nostr.protocol.Filter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * Manages Unicity nametag-to-Nostr pubkey bindings using replaceable events.
 * One-directional: nametag resolves to pubkey (not reverse).
 * Uses hashed nametags for privacy.
 */
public class NametagBinding {

    private static final Logger logger = LoggerFactory.getLogger(NametagBinding.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Extended identity parameters for richer binding events.
     * All fields are optional — when provided, they are included in the
     * event content and indexed via 't' tags for reverse lookup.
     */
    public static class IdentityBindingParams {
        /** 33-byte compressed secp256k1 public key */
        private String publicKey;
        /** L1 bech32 address (e.g., alpha1...) */
        private String l1Address;
        /** Direct address identifier */
        private String directAddress;
        /** Proxy address (derived from nametag) */
        private String proxyAddress;

        public IdentityBindingParams() {}

        public IdentityBindingParams(String publicKey, String l1Address, String directAddress, String proxyAddress) {
            this.publicKey = publicKey;
            this.l1Address = l1Address;
            this.directAddress = directAddress;
            this.proxyAddress = proxyAddress;
        }

        public String getPublicKey() { return publicKey; }
        public void setPublicKey(String publicKey) { this.publicKey = publicKey; }

        public String getL1Address() { return l1Address; }
        public void setL1Address(String l1Address) { this.l1Address = l1Address; }

        public String getDirectAddress() { return directAddress; }
        public void setDirectAddress(String directAddress) { this.directAddress = directAddress; }

        public String getProxyAddress() { return proxyAddress; }
        public void setProxyAddress(String proxyAddress) { this.proxyAddress = proxyAddress; }
    }

    /**
     * Parsed binding info returned by query methods.
     */
    public static class BindingInfo {
        /** Event author's 32-byte Nostr public key (hex) */
        private final String transportPubkey;
        /** 33-byte compressed secp256k1 public key (from content) */
        private final String publicKey;
        /** L1 bech32 address (from content) */
        private final String l1Address;
        /** Direct address (from content) */
        private final String directAddress;
        /** Proxy address (from content) */
        private final String proxyAddress;
        /** Plaintext nametag (from content, if present) */
        private final String nametag;
        /** Event timestamp in milliseconds */
        private final long timestamp;

        public BindingInfo(String transportPubkey, String publicKey, String l1Address,
                          String directAddress, String proxyAddress, String nametag, long timestamp) {
            this.transportPubkey = transportPubkey;
            this.publicKey = publicKey;
            this.l1Address = l1Address;
            this.directAddress = directAddress;
            this.proxyAddress = proxyAddress;
            this.nametag = nametag;
            this.timestamp = timestamp;
        }

        public String getTransportPubkey() { return transportPubkey; }
        public String getPublicKey() { return publicKey; }
        public String getL1Address() { return l1Address; }
        public String getDirectAddress() { return directAddress; }
        public String getProxyAddress() { return proxyAddress; }
        public String getNametag() { return nametag; }
        public long getTimestamp() { return timestamp; }
    }

    /**
     * Create a nametag binding event with identity parameters.
     * Validates the nametag, creates indexed tags for reverse lookup,
     * and optionally includes extended identity fields.
     *
     * @param keyManager the key manager for signing
     * @param nametagId Nametag identifier (e.g., "alice@unicity" or phone number)
     * @param unicityAddress Unicity blockchain address
     * @param defaultCountry Default country for phone normalization (e.g., "US")
     * @param identity Optional extended identity parameters
     * @return Signed binding event
     * @throws Exception if nametag is invalid or event creation fails
     */
    public static Event createBindingEvent(NostrKeyManager keyManager, String nametagId,
                                          String unicityAddress, String defaultCountry,
                                          IdentityBindingParams identity) throws Exception {
        if (!NametagUtils.isValidNametag(nametagId, defaultCountry)) {
            throw new IllegalArgumentException(
                "Invalid nametag: \"" + nametagId + "\". Must be 3-20 chars [a-z0-9_-] or a valid phone number.");
        }

        long createdAt = System.currentTimeMillis() / 1000;
        String hashedNametag = NametagUtils.hashNametag(nametagId, defaultCountry);

        // Create tags
        List<List<String>> tags = new ArrayList<>();
        tags.add(Arrays.asList("d", hashedNametag));
        tags.add(Arrays.asList("nametag", hashedNametag));
        tags.add(Arrays.asList("t", hashedNametag));
        tags.add(Arrays.asList("address", unicityAddress));
        tags.add(Arrays.asList("t", NametagUtils.hashAddressForTag(unicityAddress)));

        // Create content
        Map<String, Object> contentData = new LinkedHashMap<>();
        contentData.put("nametag_hash", hashedNametag);
        contentData.put("address", unicityAddress);
        contentData.put("verified", System.currentTimeMillis() / 1000);

        // Add extended identity fields when provided
        if (identity != null) {
            String encryptedNametag = NametagUtils.encryptNametag(
                nametagId, keyManager.getPrivateKeyHex());
            contentData.put("encrypted_nametag", encryptedNametag);
            contentData.put("nametag", nametagId);

            if (identity.getPublicKey() != null) {
                contentData.put("public_key", identity.getPublicKey());
                tags.add(Arrays.asList("t", NametagUtils.hashAddressForTag(identity.getPublicKey())));
                tags.add(Arrays.asList("pubkey", identity.getPublicKey()));
            }
            if (identity.getL1Address() != null) {
                contentData.put("l1_address", identity.getL1Address());
                tags.add(Arrays.asList("t", NametagUtils.hashAddressForTag(identity.getL1Address())));
                tags.add(Arrays.asList("l1", identity.getL1Address()));
            }
            if (identity.getDirectAddress() != null) {
                contentData.put("direct_address", identity.getDirectAddress());
                tags.add(Arrays.asList("t", NametagUtils.hashAddressForTag(identity.getDirectAddress())));
            }
            if (identity.getProxyAddress() != null) {
                contentData.put("proxy_address", identity.getProxyAddress());
                tags.add(Arrays.asList("t", NametagUtils.hashAddressForTag(identity.getProxyAddress())));
            }
        }

        String content = JSON.writeValueAsString(contentData);

        // Create event for signing
        Event event = new Event();
        event.setPubkey(keyManager.getPublicKeyHex());
        event.setCreatedAt(createdAt);
        event.setKind(EventKinds.APP_DATA);
        event.setTags(tags);
        event.setContent(content);

        // Calculate event ID and sign
        String eventId = calculateEventId(event);
        event.setId(eventId);
        byte[] eventIdBytes = Hex.decodeHex(eventId.toCharArray());
        String signature = keyManager.signHex(eventIdBytes);
        event.setSig(signature);

        return event;
    }

    /**
     * Create a nametag binding event (no identity params).
     */
    public static Event createBindingEvent(NostrKeyManager keyManager, String nametagId,
                                          String unicityAddress, String defaultCountry) throws Exception {
        return createBindingEvent(keyManager, nametagId, unicityAddress, defaultCountry, null);
    }

    /**
     * Create a nametag binding event with default country "US".
     */
    public static Event createBindingEvent(NostrKeyManager keyManager, String nametagId,
                                          String unicityAddress) throws Exception {
        return createBindingEvent(keyManager, nametagId, unicityAddress, "US", null);
    }

    /**
     * Create a base identity binding event (no nametag).
     * Uses d-tag = SHA256('unicity:identity:' + nostrPubkey) so each wallet
     * has exactly one identity binding event. Subsequent calls replace the previous event.
     *
     * @param keyManager Key manager with signing keys
     * @param identity Identity parameters (publicKey, l1Address, directAddress)
     * @return Signed event
     * @throws Exception if event creation or signing fails
     */
    public static Event createIdentityBindingEvent(NostrKeyManager keyManager,
                                                    IdentityBindingParams identity) throws Exception {
        String nostrPubkey = keyManager.getPublicKeyHex();
        String dTag = NametagUtils.sha256Hex("unicity:identity:" + nostrPubkey);

        Map<String, Object> contentData = new LinkedHashMap<>();
        List<List<String>> tags = new ArrayList<>();
        tags.add(Arrays.asList("d", dTag));

        if (identity.getPublicKey() != null) {
            contentData.put("public_key", identity.getPublicKey());
            tags.add(Arrays.asList("t", NametagUtils.hashAddressForTag(identity.getPublicKey())));
        }
        if (identity.getL1Address() != null) {
            contentData.put("l1_address", identity.getL1Address());
            tags.add(Arrays.asList("t", NametagUtils.hashAddressForTag(identity.getL1Address())));
        }
        if (identity.getDirectAddress() != null) {
            contentData.put("direct_address", identity.getDirectAddress());
            tags.add(Arrays.asList("t", NametagUtils.hashAddressForTag(identity.getDirectAddress())));
        }
        if (identity.getProxyAddress() != null) {
            contentData.put("proxy_address", identity.getProxyAddress());
            tags.add(Arrays.asList("t", NametagUtils.hashAddressForTag(identity.getProxyAddress())));
        }

        String content = JSON.writeValueAsString(contentData);
        long createdAt = System.currentTimeMillis() / 1000;

        Event event = new Event();
        event.setPubkey(keyManager.getPublicKeyHex());
        event.setCreatedAt(createdAt);
        event.setKind(EventKinds.APP_DATA);
        event.setTags(tags);
        event.setContent(content);

        String eventId = calculateEventId(event);
        event.setId(eventId);
        byte[] eventIdBytes = Hex.decodeHex(eventId.toCharArray());
        String signature = keyManager.signHex(eventIdBytes);
        event.setSig(signature);

        return event;
    }

    /**
     * Create a filter to find Nostr pubkey by nametag.
     * No limit is set so the relay returns all matching events,
     * allowing first-seen-wins resolution across authors.
     *
     * @param nametagId Nametag identifier
     * @param defaultCountry Default country for phone normalization
     * @return Filter for querying the binding
     */
    public static Filter createNametagToPubkeyFilter(String nametagId, String defaultCountry) {
        String hashedNametag = NametagUtils.hashNametag(nametagId, defaultCountry);

        return Filter.builder()
            .kinds(EventKinds.APP_DATA)
            .tTags(hashedNametag)
            .build();
    }

    /**
     * Create a filter to find Nostr pubkey by nametag (default country "US").
     */
    public static Filter createNametagToPubkeyFilter(String nametagId) {
        return createNametagToPubkeyFilter(nametagId, "US");
    }

    /**
     * Create a filter to query binding events by address hash.
     * Query direction: address to binding event.
     *
     * @param address Address string (DIRECT://..., alpha1..., PROXY://..., or chain pubkey)
     * @return Filter for nametag binding events
     */
    public static Filter createAddressToBindingFilter(String address) {
        String hashedAddress = NametagUtils.hashAddressForTag(address);

        return Filter.builder()
            .kinds(EventKinds.APP_DATA)
            .tTags(hashedAddress)
            .build();
    }

    /**
     * Create a filter to find nametags by Nostr pubkey.
     *
     * @param nostrPubkey Nostr public key (hex)
     * @return Filter for querying bindings by pubkey
     */
    public static Filter createPubkeyToNametagFilter(String nostrPubkey) {
        return Filter.builder()
            .kinds(EventKinds.APP_DATA)
            .authors(nostrPubkey)
            .limit(10)
            .build();
    }

    /**
     * Parse binding info from an event.
     * Extracts both basic and extended identity fields from event content.
     * On parse failure, returns minimal binding info.
     *
     * @param event Binding event
     * @return BindingInfo with parsed fields
     */
    public static BindingInfo parseBindingInfo(Event event) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> contentData = JSON.readValue(event.getContent(), Map.class);
            return new BindingInfo(
                event.getPubkey(),
                (String) contentData.get("public_key"),
                (String) contentData.get("l1_address"),
                (String) contentData.get("direct_address"),
                (String) contentData.get("proxy_address"),
                (String) contentData.get("nametag"),
                event.getCreatedAt() * 1000
            );
        } catch (Exception e) {
            logger.warn("Failed to parse binding event content (event {}): {}",
                event.getId() != null ? event.getId().substring(0, Math.min(8, event.getId().length())) : "null",
                e.getMessage());
            return new BindingInfo(
                event.getPubkey(),
                null, null, null, null, null,
                event.getCreatedAt() * 1000
            );
        }
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

        for (List<String> tag : event.getTags()) {
            if (tag.size() >= 2 && "nametag".equals(tag.get(0))) {
                return tag.get(1);
            }
        }

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

        for (List<String> tag : event.getTags()) {
            if (tag.size() >= 2 && "address".equals(tag.get(0))) {
                return tag.get(1);
            }
        }

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

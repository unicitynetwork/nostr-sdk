package org.unicitylabs.nostr.messaging;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * NIP-17 Rumor - An unsigned inner event for private direct messages.
 * Rumors are wrapped in seals and gift wraps for sender privacy.
 *
 * Unlike regular Events, Rumors do NOT have a signature field.
 */
public class Rumor {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Event ID (SHA-256 hash of serialized rumor) */
    @JsonProperty("id")
    private String id;

    /** Public key of rumor creator (real sender) */
    @JsonProperty("pubkey")
    private String pubkey;

    /** Unix timestamp in seconds */
    @JsonProperty("created_at")
    private long createdAt;

    /** Event kind (14 for chat message, 15 for read receipt) */
    @JsonProperty("kind")
    private int kind;

    /** Event tags */
    @JsonProperty("tags")
    private List<List<String>> tags;

    /** Message content */
    @JsonProperty("content")
    private String content;

    /**
     * Default constructor for Jackson deserialization.
     */
    public Rumor() {
        this.tags = new ArrayList<>();
        this.content = "";
    }

    /**
     * Create a rumor with all fields.
     */
    public Rumor(String pubkey, long createdAt, int kind, List<List<String>> tags, String content) {
        this.pubkey = pubkey;
        this.createdAt = createdAt;
        this.kind = kind;
        this.tags = tags != null ? new ArrayList<>(tags) : new ArrayList<>();
        this.content = content != null ? content : "";
        this.id = computeId();
    }

    // Getters
    public String getId() { return id; }
    public String getPubkey() { return pubkey; }
    public long getCreatedAt() { return createdAt; }
    public int getKind() { return kind; }
    public List<List<String>> getTags() { return tags; }
    public String getContent() { return content; }

    // Setters
    public void setId(String id) { this.id = id; }
    public void setPubkey(String pubkey) { this.pubkey = pubkey; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    public void setKind(int kind) { this.kind = kind; }
    public void setTags(List<List<String>> tags) { this.tags = tags != null ? new ArrayList<>(tags) : new ArrayList<>(); }
    public void setContent(String content) { this.content = content != null ? content : ""; }

    /**
     * Get the value of a tag by name.
     */
    public String getTagValue(String tagName) {
        for (List<String> tag : tags) {
            if (!tag.isEmpty() && tag.get(0).equals(tagName) && tag.size() > 1) {
                return tag.get(1);
            }
        }
        return null;
    }

    /**
     * Compute the event ID from serialized data.
     * ID = SHA-256([0, pubkey, created_at, kind, tags, content])
     */
    private String computeId() {
        try {
            // Serialize as JSON array: [0, pubkey, created_at, kind, tags, content]
            StringBuilder sb = new StringBuilder();
            sb.append("[0,\"");
            sb.append(pubkey);
            sb.append("\",");
            sb.append(createdAt);
            sb.append(",");
            sb.append(kind);
            sb.append(",");
            sb.append(MAPPER.writeValueAsString(tags));
            sb.append(",");
            sb.append(MAPPER.writeValueAsString(content));
            sb.append("]");

            byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(bytes);

            return bytesToHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute rumor ID", e);
        }
    }

    /**
     * Serialize rumor to JSON string.
     */
    public String toJson() throws JsonProcessingException {
        return MAPPER.writeValueAsString(this);
    }

    /**
     * Deserialize rumor from JSON string.
     */
    public static Rumor fromJson(String json) throws JsonProcessingException {
        return MAPPER.readValue(json, Rumor.class);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return "Rumor{" +
                "id='" + (id != null ? id.substring(0, Math.min(16, id.length())) : "null") + "...'" +
                ", pubkey='" + (pubkey != null ? pubkey.substring(0, Math.min(16, pubkey.length())) : "null") + "...'" +
                ", kind=" + kind +
                ", createdAt=" + createdAt +
                ", content=" + content.length() + " chars" +
                '}';
    }
}

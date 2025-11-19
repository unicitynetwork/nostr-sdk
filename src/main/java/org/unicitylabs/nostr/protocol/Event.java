package org.unicitylabs.nostr.protocol;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Nostr event structure as defined in NIP-01.
 * Events are the fundamental building blocks of the Nostr protocol.
 */
public class Event {

    /** Event ID (32-byte SHA-256 hash of serialized event data) */
    @JsonProperty("id")
    private String id;

    /** Public key of event creator (32-byte hex string) */
    @JsonProperty("pubkey")
    private String pubkey;

    /** Unix timestamp in seconds */
    @JsonProperty("created_at")
    private long createdAt;

    /** Event kind (determines event type and handling) */
    @JsonProperty("kind")
    private int kind;

    /** Event tags (list of tag arrays) */
    @JsonProperty("tags")
    private List<List<String>> tags;

    /** Event content (arbitrary string, often JSON) */
    @JsonProperty("content")
    private String content;

    /** Schnorr signature (64-byte hex string) */
    @JsonProperty("sig")
    private String sig;

    /**
     * Default constructor for Jackson deserialization.
     */
    public Event() {
        this.tags = new ArrayList<>();
        this.content = "";
    }

    /**
     * Full constructor for creating events.
     */
    public Event(String id, String pubkey, long createdAt, int kind,
                 List<List<String>> tags, String content, String sig) {
        this.id = id;
        this.pubkey = pubkey;
        this.createdAt = createdAt;
        this.kind = kind;
        this.tags = tags != null ? new ArrayList<>(tags) : new ArrayList<>();
        this.content = content != null ? content : "";
        this.sig = sig;
    }

    // Getters
    public String getId() { return id; }
    public String getPubkey() { return pubkey; }
    public long getCreatedAt() { return createdAt; }
    public int getKind() { return kind; }
    public List<List<String>> getTags() { return tags; }
    public String getContent() { return content; }
    public String getSig() { return sig; }

    // Setters
    public void setId(String id) { this.id = id; }
    public void setPubkey(String pubkey) { this.pubkey = pubkey; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    public void setKind(int kind) { this.kind = kind; }
    public void setTags(List<List<String>> tags) {
        this.tags = tags != null ? new ArrayList<>(tags) : new ArrayList<>();
    }
    public void setContent(String content) {
        this.content = content != null ? content : "";
    }
    public void setSig(String sig) { this.sig = sig; }

    /**
     * Get the value of a single-letter tag (e.g., "p", "e", "t").
     * Returns the first occurrence of the tag value.
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
     * Get all values of a single-letter tag.
     */
    public List<String> getTagValues(String tagName) {
        List<String> values = new ArrayList<>();
        for (List<String> tag : tags) {
            if (!tag.isEmpty() && tag.get(0).equals(tagName) && tag.size() > 1) {
                values.add(tag.get(1));
            }
        }
        return values;
    }

    /**
     * Check if event has a specific tag.
     */
    public boolean hasTag(String tagName) {
        return tags.stream()
            .anyMatch(tag -> !tag.isEmpty() && tag.get(0).equals(tagName));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Event event = (Event) o;
        return Objects.equals(id, event.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "Event{" +
                "id='" + (id != null ? id.substring(0, Math.min(16, id.length())) : "null") + "...'" +
                ", pubkey='" + (pubkey != null ? pubkey.substring(0, Math.min(16, pubkey.length())) : "null") + "...'" +
                ", kind=" + kind +
                ", createdAt=" + createdAt +
                ", tags=" + tags.size() +
                ", content=" + content.length() + " chars" +
                '}';
    }
}

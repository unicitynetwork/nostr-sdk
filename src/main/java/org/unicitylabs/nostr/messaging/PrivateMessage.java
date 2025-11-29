package org.unicitylabs.nostr.messaging;

/**
 * Parsed private message from NIP-17 gift-wrapped event.
 * Contains the decrypted message content and metadata.
 */
public class PrivateMessage {

    /** Nostr event ID of the gift wrap (for deduplication) */
    private final String eventId;

    /** Sender's public key (from the seal, not the gift wrap) */
    private final String senderPubkey;

    /** Sender's nametag (Unicity ID) if provided */
    private final String senderNametag;

    /** Recipient's public key */
    private final String recipientPubkey;

    /** Message content */
    private final String content;

    /** Message timestamp (from the rumor) */
    private final long timestamp;

    /** Original rumor kind (14 for chat, 15 for read receipt) */
    private final int kind;

    /** Reply-to event ID (if this is a reply) */
    private final String replyToEventId;

    /**
     * Create a parsed private message.
     */
    public PrivateMessage(String eventId, String senderPubkey, String senderNametag,
                          String recipientPubkey, String content, long timestamp,
                          int kind, String replyToEventId) {
        this.eventId = eventId;
        this.senderPubkey = senderPubkey;
        this.senderNametag = senderNametag;
        this.recipientPubkey = recipientPubkey;
        this.content = content;
        this.timestamp = timestamp;
        this.kind = kind;
        this.replyToEventId = replyToEventId;
    }

    /**
     * Builder for creating PrivateMessage instances.
     */
    public static class Builder {
        private String eventId;
        private String senderPubkey;
        private String senderNametag;
        private String recipientPubkey;
        private String content;
        private long timestamp;
        private int kind;
        private String replyToEventId;

        public Builder eventId(String eventId) {
            this.eventId = eventId;
            return this;
        }

        public Builder senderPubkey(String senderPubkey) {
            this.senderPubkey = senderPubkey;
            return this;
        }

        public Builder senderNametag(String senderNametag) {
            this.senderNametag = senderNametag;
            return this;
        }

        public Builder recipientPubkey(String recipientPubkey) {
            this.recipientPubkey = recipientPubkey;
            return this;
        }

        public Builder content(String content) {
            this.content = content;
            return this;
        }

        public Builder timestamp(long timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder kind(int kind) {
            this.kind = kind;
            return this;
        }

        public Builder replyToEventId(String replyToEventId) {
            this.replyToEventId = replyToEventId;
            return this;
        }

        public PrivateMessage build() {
            return new PrivateMessage(eventId, senderPubkey, senderNametag,
                    recipientPubkey, content, timestamp, kind, replyToEventId);
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    // Getters
    public String getEventId() { return eventId; }
    public String getSenderPubkey() { return senderPubkey; }
    public String getSenderNametag() { return senderNametag; }
    public String getRecipientPubkey() { return recipientPubkey; }
    public String getContent() { return content; }
    public long getTimestamp() { return timestamp; }
    public int getKind() { return kind; }
    public String getReplyToEventId() { return replyToEventId; }

    /**
     * Check if this is a chat message (kind 14).
     */
    public boolean isChatMessage() {
        return kind == 14;
    }

    /**
     * Check if this is a read receipt (kind 15).
     */
    public boolean isReadReceipt() {
        return kind == 15;
    }

    @Override
    public String toString() {
        return "PrivateMessage{" +
                "eventId='" + (eventId != null ? eventId.substring(0, Math.min(16, eventId.length())) : "null") + "...'" +
                ", senderPubkey='" + (senderPubkey != null ? senderPubkey.substring(0, Math.min(16, senderPubkey.length())) : "null") + "...'" +
                ", kind=" + kind +
                ", timestamp=" + timestamp +
                ", content=" + content.length() + " chars" +
                '}';
    }
}

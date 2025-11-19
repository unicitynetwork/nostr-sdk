package org.unicitylabs.nostr.protocol;

/**
 * Nostr event kinds as defined in various NIPs.
 * See: https://github.com/nostr-protocol/nips
 */
public final class EventKinds {

    // Standard NIPs

    /** NIP-01: Metadata (profile information) */
    public static final int PROFILE = 0;

    /** NIP-01: Text note */
    public static final int TEXT_NOTE = 1;

    /** NIP-01: Recommend relay */
    public static final int RECOMMEND_RELAY = 2;

    /** NIP-02: Contact list */
    public static final int CONTACTS = 3;

    /** NIP-04: Encrypted direct message */
    public static final int ENCRYPTED_DM = 4;

    /** NIP-09: Event deletion */
    public static final int DELETION = 5;

    /** NIP-25: Reactions */
    public static final int REACTION = 7;

    /** NIP-59: Gift wrap (sealed, private message) */
    public static final int GIFT_WRAP = 1059;

    /** NIP-65: Relay list metadata */
    public static final int RELAY_LIST = 10002;

    /** NIP-78: Application-specific data (parameterized replaceable) */
    public static final int APP_DATA = 30078;

    // Unicity Custom Event Kinds (31000-31999 reserved for custom use)

    /** Unicity: Agent profile information */
    public static final int AGENT_PROFILE = 31111;

    /** Unicity: Agent location broadcast (GPS coordinates) */
    public static final int AGENT_LOCATION = 31112;

    /** Unicity: Token transfer message */
    public static final int TOKEN_TRANSFER = 31113;

    /** Unicity: File metadata for large transfers */
    public static final int FILE_METADATA = 31114;

    // Ranges

    /** Replaceable events: only most recent event is kept */
    public static boolean isReplaceable(int kind) {
        return (kind == 0 || kind == 3 || (kind >= 10000 && kind < 20000));
    }

    /** Ephemeral events: not stored by relays */
    public static boolean isEphemeral(int kind) {
        return (kind >= 20000 && kind < 30000);
    }

    /** Parameterized replaceable events: replaceable per "d" tag */
    public static boolean isParameterizedReplaceable(int kind) {
        return (kind >= 30000 && kind < 40000);
    }

    /**
     * Get human-readable name for event kind.
     */
    public static String getName(int kind) {
        switch (kind) {
            case PROFILE: return "Profile";
            case TEXT_NOTE: return "Text Note";
            case RECOMMEND_RELAY: return "Recommend Relay";
            case CONTACTS: return "Contacts";
            case ENCRYPTED_DM: return "Encrypted DM";
            case DELETION: return "Deletion";
            case REACTION: return "Reaction";
            case GIFT_WRAP: return "Gift Wrap";
            case RELAY_LIST: return "Relay List";
            case APP_DATA: return "App Data";
            case AGENT_PROFILE: return "Agent Profile";
            case AGENT_LOCATION: return "Agent Location";
            case TOKEN_TRANSFER: return "Token Transfer";
            case FILE_METADATA: return "File Metadata";
            default: return "Unknown (" + kind + ")";
        }
    }

    private EventKinds() {
        // Utility class, no instantiation
    }
}

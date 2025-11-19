package org.unicitylabs.nostr.client;

import org.unicitylabs.nostr.protocol.Event;

/**
 * Listener interface for receiving Nostr events from subscriptions.
 */
public interface NostrEventListener {

    /**
     * Called when an event matching the subscription filter is received.
     *
     * @param event The received event
     */
    void onEvent(Event event);

    /**
     * Called when End-Of-Stored-Events (EOSE) is received for a subscription.
     * Optional: default implementation does nothing.
     *
     * @param subscriptionId The subscription ID
     */
    default void onEndOfStoredEvents(String subscriptionId) {
        // Optional callback
    }

    /**
     * Called when a subscription encounters an error.
     * Optional: default implementation does nothing.
     *
     * @param subscriptionId The subscription ID
     * @param error Error message
     */
    default void onError(String subscriptionId, String error) {
        // Optional callback
    }
}

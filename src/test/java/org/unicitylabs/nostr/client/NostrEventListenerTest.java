package org.unicitylabs.nostr.client;

import org.junit.Test;
import org.unicitylabs.nostr.protocol.Event;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

/**
 * Tests for NostrEventListener callback patterns.
 * Verifies callback invocation and error handling.
 *
 * Techniques: [UC] Use Case Testing
 */
public class NostrEventListenerTest {

    // ==========================================================
    // onEvent Callback Tests
    // ==========================================================

    @Test
    public void testOnEventCallbackInvokedWithEvent() {
        List<Event> receivedEvents = new ArrayList<>();

        NostrEventListener listener = new NostrEventListener() {
            @Override
            public void onEvent(Event event) {
                receivedEvents.add(event);
            }
        };

        Event testEvent = new Event("id", "pubkey", 1000, 1,
                new ArrayList<>(), "content", "sig");

        listener.onEvent(testEvent);

        assertEquals(1, receivedEvents.size());
        assertEquals("id", receivedEvents.get(0).getId());
    }

    @Test
    public void testOnEventMultipleEvents() {
        AtomicInteger callCount = new AtomicInteger(0);

        NostrEventListener listener = new NostrEventListener() {
            @Override
            public void onEvent(Event event) {
                callCount.incrementAndGet();
            }
        };

        for (int i = 0; i < 10; i++) {
            Event event = new Event("id" + i, "pk", 1000, 1, new ArrayList<>(), "c", "sig");
            listener.onEvent(event);
        }

        assertEquals(10, callCount.get());
    }

    // ==========================================================
    // onEndOfStoredEvents Callback Tests
    // ==========================================================

    @Test
    public void testOnEndOfStoredEventsCallbackInvoked() {
        List<String> subscriptionIds = new ArrayList<>();

        NostrEventListener listener = new NostrEventListener() {
            @Override
            public void onEvent(Event event) {}

            @Override
            public void onEndOfStoredEvents(String subscriptionId) {
                subscriptionIds.add(subscriptionId);
            }
        };

        listener.onEndOfStoredEvents("sub_123");

        assertEquals(1, subscriptionIds.size());
        assertEquals("sub_123", subscriptionIds.get(0));
    }

    @Test
    public void testOnEndOfStoredEventsDefaultMethodDoesNotThrow() {
        NostrEventListener listener = new NostrEventListener() {
            @Override
            public void onEvent(Event event) {}
        };

        // Default implementation should not throw
        listener.onEndOfStoredEvents("sub_123");
    }

    // ==========================================================
    // onError Callback Tests
    // ==========================================================

    @Test
    public void testOnErrorCallbackInvoked() {
        List<String> errors = new ArrayList<>();

        NostrEventListener listener = new NostrEventListener() {
            @Override
            public void onEvent(Event event) {}

            @Override
            public void onError(String subscriptionId, String errorMessage) {
                errors.add(subscriptionId + ":" + errorMessage);
            }
        };

        listener.onError("sub_456", "auth-required: must authenticate");

        assertEquals(1, errors.size());
        assertEquals("sub_456:auth-required: must authenticate", errors.get(0));
    }

    @Test
    public void testOnErrorDefaultMethodDoesNotThrow() {
        NostrEventListener listener = new NostrEventListener() {
            @Override
            public void onEvent(Event event) {}
        };

        // Default implementation should not throw
        listener.onError("sub_456", "some error");
    }

    // ==========================================================
    // Interface Default Methods
    // ==========================================================

    @Test
    public void testInterfaceHasDefaultMethods() {
        // Create minimal implementation - only onEvent required
        NostrEventListener listener = event -> {};

        // These should not throw (default methods are no-ops)
        listener.onEndOfStoredEvents("sub");
        listener.onError("sub", "error");
    }

    // ==========================================================
    // Callback Pattern Tests
    // ==========================================================

    @Test
    public void testCallbacksInvokedInCorrectOrder() {
        List<String> callOrder = new ArrayList<>();

        NostrEventListener listener = new NostrEventListener() {
            @Override
            public void onEvent(Event event) {
                callOrder.add("event:" + event.getId());
            }

            @Override
            public void onEndOfStoredEvents(String subscriptionId) {
                callOrder.add("eose:" + subscriptionId);
            }

            @Override
            public void onError(String subscriptionId, String errorMessage) {
                callOrder.add("error:" + subscriptionId);
            }
        };

        // Simulate typical relay response sequence
        listener.onEvent(new Event("e1", "pk", 1000, 1, new ArrayList<>(), "", "sig"));
        listener.onEvent(new Event("e2", "pk", 1001, 1, new ArrayList<>(), "", "sig"));
        listener.onEndOfStoredEvents("sub_1");

        assertEquals(3, callOrder.size());
        assertEquals("event:e1", callOrder.get(0));
        assertEquals("event:e2", callOrder.get(1));
        assertEquals("eose:sub_1", callOrder.get(2));
    }

    @Test
    public void testErrorCallbackWithClosedMessage() {
        List<String> errors = new ArrayList<>();

        NostrEventListener listener = new NostrEventListener() {
            @Override
            public void onEvent(Event event) {}

            @Override
            public void onError(String subscriptionId, String errorMessage) {
                errors.add(errorMessage);
            }
        };

        // Simulate CLOSED message from relay
        listener.onError("sub_1", "auth-required: must authenticate");
        listener.onError("sub_2", "rate-limited: too many requests");

        assertEquals(2, errors.size());
        assertTrue(errors.get(0).contains("auth-required"));
        assertTrue(errors.get(1).contains("rate-limited"));
    }

    // ==========================================================
    // Lambda Implementation Tests
    // ==========================================================

    @Test
    public void testLambdaImplementation() {
        AtomicInteger eventCount = new AtomicInteger(0);

        // Can use lambda for onEvent-only implementation
        NostrEventListener listener = event -> eventCount.incrementAndGet();

        Event testEvent = new Event("id", "pk", 1000, 1, new ArrayList<>(), "", "sig");
        listener.onEvent(testEvent);
        listener.onEvent(testEvent);

        assertEquals(2, eventCount.get());
    }

    @Test
    public void testAnonymousClassFullImplementation() {
        AtomicInteger eventCount = new AtomicInteger(0);
        AtomicInteger eoseCount = new AtomicInteger(0);
        AtomicInteger errorCount = new AtomicInteger(0);

        NostrEventListener listener = new NostrEventListener() {
            @Override
            public void onEvent(Event event) {
                eventCount.incrementAndGet();
            }

            @Override
            public void onEndOfStoredEvents(String subscriptionId) {
                eoseCount.incrementAndGet();
            }

            @Override
            public void onError(String subscriptionId, String errorMessage) {
                errorCount.incrementAndGet();
            }
        };

        listener.onEvent(new Event("id", "pk", 1000, 1, new ArrayList<>(), "", "sig"));
        listener.onEndOfStoredEvents("sub");
        listener.onError("sub", "error");

        assertEquals(1, eventCount.get());
        assertEquals(1, eoseCount.get());
        assertEquals(1, errorCount.get());
    }
}

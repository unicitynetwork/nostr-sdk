# Unicity Nostr SDK

Java SDK for Nostr protocol integration with Unicity blockchain applications.

## Features

- **NIP-17 Private Messages**: Gift-wrapped private direct messages with sender anonymity
- **NIP-44 Encryption**: Modern ChaCha20-Poly1305 AEAD encryption with HKDF key derivation
- **Token Transfers**: Send and receive Unicity tokens via Nostr encrypted messages
- **Payment Requests**: Request payments from other users via encrypted Nostr messages
- **Nametag Bindings**: Map Unicity nametags to Nostr public keys for discovery
- **NIP-04 Encryption**: Legacy AES-CBC encrypted direct messages with automatic compression
- **Location Broadcasting**: Agent location discovery for P2P networks
- **Profile Management**: Standard Nostr profiles (NIP-01)
- **Multi-Relay Support**: Connect to multiple Nostr relays simultaneously
- **Pure Java**: No JNI dependencies, works on Android and JVM

## Requirements

- Java 11 or higher
- Android API 31+ (for Android applications)

## Installation

### Gradle (JitPack)

```gradle
repositories {
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation("org.unicitylabs:nostr-sdk:0.0.5")
}
```

### Maven (JitPack)

Add JitPack repository to your `pom.xml`:

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>org.unicitylabs</groupId>
    <artifactId>nostr-sdk</artifactId>
    <version>0.0.5</version>
</dependency>
```

### Local Development

For local development, publish to mavenLocal:

```bash
./gradlew publishToMavenLocal -Pversion=0.0.5
```

Then use:

```gradle
repositories {
    mavenLocal()
}

dependencies {
    implementation("org.unicitylabs:nostr-sdk:0.0.5")
}
```

## Quick Start

### Initialize Client

```java
// Generate new keypair
NostrKeyManager keyManager = NostrKeyManager.generate();

// Or create from existing private key
byte[] privateKey = ...; // 32-byte private key
NostrKeyManager keyManager = NostrKeyManager.fromPrivateKey(privateKey);

// Create client
NostrClient client = new NostrClient(keyManager);

// Connect to relays
client.connect("wss://relay.example.com").get();
```

### Send Encrypted Message (NIP-04 Legacy)

```java
String recipientPubkey = "...";
String message = "Hello, Nostr!";

client.publishEncryptedMessage(recipientPubkey, message)
    .thenAccept(eventId -> {
        System.out.println("Message sent: " + eventId);
    });
```

### NIP-17 Private Messages (Recommended)

NIP-17 provides enhanced privacy using gift-wrapping with ephemeral keys:

```java
// Send private message by nametag (auto-resolves to pubkey)
client.sendPrivateMessageToNametag("alice", "Hello Alice!", "bob")  // from bob
    .thenAccept(eventId -> {
        System.out.println("Message sent: " + eventId);
    });

// Or send by pubkey directly with sender identification
String recipientPubkey = "...";
String senderNametag = "bob";  // Sender's nametag for receiver to identify
client.sendPrivateMessage(recipientPubkey, "Hello!", null, senderNametag)
    .thenAccept(eventId -> {
        System.out.println("Message sent: " + eventId);
    });

// Send reply to a previous message
String replyToEventId = "..."; // Event ID of message being replied to
client.sendPrivateMessage(recipientPubkey, "This is a reply!", replyToEventId, senderNametag)
    .thenAccept(eventId -> {
        System.out.println("Reply sent: " + eventId);
    });

// Send read receipt
String originalEventId = "..."; // Event ID of message being acknowledged
client.sendReadReceipt(senderPubkey, originalEventId)
    .thenAccept(eventId -> {
        System.out.println("Read receipt sent: " + eventId);
    });
```

Receive and unwrap private messages:

```java
// Subscribe to gift-wrapped messages
Filter filter = Filter.builder()
    .kinds(EventKinds.GIFT_WRAP)
    .pTags(keyManager.getPublicKeyHex())
    .build();

client.subscribe("private-messages", filter, event -> {
    try {
        PrivateMessage message = client.unwrapPrivateMessage(event);

        if (message.isChatMessage()) {
            // Get sender's nametag (if included) for user-friendly display
            String senderNametag = message.getSenderNametag();
            if (senderNametag != null) {
                System.out.println("From: " + senderNametag);
            } else {
                System.out.println("From: " + message.getSenderPubkey());
            }
            System.out.println("Content: " + message.getContent());

            // Send read receipt
            client.sendReadReceipt(message.getSenderPubkey(), message.getEventId());
        } else if (message.isReadReceipt()) {
            System.out.println("Read receipt for: " + message.getReplyToEventId());
        }
    } catch (Exception e) {
        // Message not for us or decryption failed
    }
});
```

### Subscribe to Events

```java
Filter filter = Filter.builder()
    .kinds(EventKinds.ENCRYPTED_DM)
    .pTags(keyManager.getPublicKeyHex())
    .build();

client.subscribe("my-subscription", filter, event -> {
    System.out.println("Received event: " + event.getId());
});
```

### Token Transfers

```java
// Send token to recipient (by pubkey)
String recipientPubkey = "..."; // Nostr public key (hex)
String tokenJson = ...; // Unicity token transfer package JSON

client.sendTokenTransfer(recipientPubkey, tokenJson)
    .thenAccept(eventId -> {
        System.out.println("Token sent: " + eventId);
    });

// Send token in response to a payment request (correlates transfer with request)
String paymentRequestEventId = "..."; // Event ID of the original payment request
Event event = TokenTransferProtocol.createTokenTransferEvent(
    keyManager,
    recipientPubkey,
    tokenJson,
    amount,           // Optional amount for metadata
    symbol,           // Optional symbol for metadata
    paymentRequestEventId  // Links this transfer to the payment request
);
client.publishEvent(event);

// SDK automatically:
// - Adds "token_transfer:" prefix
// - Creates kind 31113 (TOKEN_TRANSFER) event
// - Encrypts with NIP-04
// - Compresses with GZIP (for payloads > 1KB)
// - Signs with Schnorr
```

### Payment Requests

Request payment from another user:

```java
import org.unicitylabs.nostr.payment.PaymentRequestProtocol;
import org.unicitylabs.nostr.payment.PaymentRequestProtocol.PaymentRequest;

// Create payment request
PaymentRequest request = new PaymentRequest(
    1000000,                    // Amount in smallest units (e.g., lamports)
    "f8aa1383...",              // Coin ID (hex)
    "SOL",                      // Symbol
    "Payment for coffee",       // Message
    "alice"                     // Recipient nametag (your nametag - where to send tokens)
);

// Resolve target's nametag to pubkey
String bobPubkey = client.queryPubkeyByNametag("bob").get();

// Send payment request
String eventId = client.sendPaymentRequest(bobPubkey, request).get();
System.out.println("Payment request sent: " + eventId);
```

Receive and parse payment requests:

```java
// Subscribe to payment requests
Filter filter = Filter.builder()
    .kinds(EventKinds.PAYMENT_REQUEST)
    .pTags(keyManager.getPublicKeyHex())
    .build();

client.subscribe("payment-requests", filter, event -> {
    try {
        PaymentRequest request = PaymentRequestProtocol.parsePaymentRequest(event, keyManager);
        System.out.println("Payment request received:");
        System.out.println("  Amount: " + request.getAmount() + " " + request.getSymbol());
        System.out.println("  Message: " + request.getMessage());
        System.out.println("  Pay to: " + request.getRecipientNametag());

        // Handle accept/reject...
    } catch (Exception e) {
        System.err.println("Failed to parse payment request: " + e.getMessage());
    }
});
```

### Nametag Bindings

```java
// Publish nametag binding (maps your nametag to your Nostr pubkey)
client.publishNametagBinding("alice", "unicity-address-here")
    .thenAccept(eventId -> {
        System.out.println("Binding published: " + eventId);
    });

// Query pubkey by nametag
String pubkey = client.queryPubkeyByNametag("alice").get();
System.out.println("Found pubkey: " + pubkey);
```

### Agent Location Broadcasting

```java
// Broadcast agent location
client.publishAgentLocation(37.7749, -122.4194, "San Francisco Agent")
    .thenAccept(eventId -> {
        System.out.println("Location published: " + eventId);
    });

// Subscribe to agent locations
Filter filter = Filter.builder()
    .kinds(EventKinds.AGENT_LOCATION)
    .since(System.currentTimeMillis() / 1000 - 3600) // Last hour
    .build();

client.subscribe("agent-locations", filter, event -> {
    // Parse location from event content
});
```

## Architecture

The SDK is organized into several packages:

| Package | Description |
|---------|-------------|
| `org.unicitylabs.nostr.client` | Main NostrClient and relay management |
| `org.unicitylabs.nostr.protocol` | Nostr protocol structures (Event, Filter, EventKinds) |
| `org.unicitylabs.nostr.crypto` | Cryptographic operations (Schnorr, NIP-04, NIP-44, Bech32) |
| `org.unicitylabs.nostr.messaging` | NIP-17 private direct messages with gift-wrapping |
| `org.unicitylabs.nostr.nametag` | Nametag binding protocol with privacy-preserving hashing |
| `org.unicitylabs.nostr.token` | Token transfer protocol with compression |
| `org.unicitylabs.nostr.payment` | Payment request protocol |

## Event Kinds

| Kind | Name | Description |
|------|------|-------------|
| 0 | PROFILE | User profile metadata (NIP-01) |
| 1 | TEXT_NOTE | Plain text note (NIP-01) |
| 4 | ENCRYPTED_DM | Encrypted direct message (NIP-04) |
| 13 | SEAL | Encrypted seal for gift-wrapping (NIP-17) |
| 14 | CHAT_MESSAGE | Private direct message rumor (NIP-17) |
| 15 | READ_RECEIPT | Read receipt rumor (NIP-17) |
| 1059 | GIFT_WRAP | Gift-wrapped message (NIP-17) |
| 30078 | APP_DATA | Nametag binding (parameterized replaceable) |
| 31111 | AGENT_PROFILE | Agent profile information |
| 31112 | AGENT_LOCATION | Agent GPS location broadcast |
| 31113 | TOKEN_TRANSFER | Unicity token transfer |
| 31114 | FILE_METADATA | File metadata for large transfers |
| 31115 | PAYMENT_REQUEST | Payment request |

## Protocol Details

### NIP-17 Private Direct Messages

NIP-17 implements private direct messages with sender anonymity using a three-layer gift-wrapping approach:

1. **Rumor** (kind 14 or 15) - Unsigned event with actual message content and real timestamp
2. **Seal** (kind 13) - Signed by sender, encrypts the rumor with NIP-44, randomized timestamp
3. **Gift Wrap** (kind 1059) - Signed by ephemeral key, encrypts the seal with NIP-44, randomized timestamp

**Benefits:**
- Sender anonymity (gift wrap uses ephemeral keys)
- End-to-end encryption with modern NIP-44 (ChaCha20-Poly1305)
- Read receipts support
- Message threading with reply references
- Timestamp randomization on outer layers for metadata privacy
- Sender nametag included for user-friendly identification
- Nametag-based addressing with auto-resolution

**Message Types:**
- **Kind 14 (CHAT_MESSAGE)**: Regular private message
- **Kind 15 (READ_RECEIPT)**: Acknowledgment that a message was read

**Rumor Tags:**
- `p` - Recipient public key
- `e` - Reply-to event ID (optional)
- `nametag` - Sender's nametag for identification (optional)

### NIP-44 Encryption

Modern authenticated encryption using:
- **ECDH**: secp256k1 shared secret derivation
- **HKDF**: Key derivation with sorted public keys as salt
- **ChaCha20-Poly1305**: AEAD cipher with 12-byte nonce
- **Padding**: Power-of-2 chunk padding to hide message length

### Token Transfer Protocol

- **Prefix**: `token_transfer:`
- **Event Kind**: 31113
- **Encryption**: NIP-04
- **Compression**: GZIP (auto for payloads > 1KB)
- **Content**: `token_transfer:{sourceToken, transferTx}`
- **Optional Tags**:
  - `["e", "<event_id>", "", "reply"]` - References a payment request event

#### Correlating Token Transfers with Payment Requests

When a user pays in response to a payment request, include the request's event ID:

```java
// Server: Send payment request, track by event ID
Map<String, PaymentRequest> pendingRequests = new ConcurrentHashMap<>();
Event requestEvent = PaymentRequestProtocol.createPaymentRequestEvent(keyManager, targetPubkey, request);
client.publishEvent(requestEvent);
pendingRequests.put(requestEvent.getId(), request);

// Server: Receive token transfer and correlate
client.subscribe(tokenFilter, event -> {
    String replyToId = TokenTransferProtocol.getReplyToEventId(event);
    if (replyToId != null) {
        PaymentRequest originalRequest = pendingRequests.get(replyToId);
        if (originalRequest != null) {
            // Payment matched to request!
            processPayment(originalRequest, event);
            pendingRequests.remove(replyToId);
        }
    }
});
```

### Payment Request Protocol

- **Prefix**: `payment_request:`
- **Event Kind**: 31115
- **Encryption**: NIP-04
- **Content**: JSON with amount, coinId, symbol, message, recipientNametag, requestId
- **Tags**: `p` (target), `type`, `amount`, `symbol`, `recipient`

See [PAYMENT_REQUEST_PROTOCOL.md](PAYMENT_REQUEST_PROTOCOL.md) for detailed protocol documentation.

### Nametag Binding Protocol

- **Event Kind**: 30078 (parameterized replaceable)
- **Privacy**: Nametags are hashed before publishing
- **Tags**: `d` (hashed nametag), `nametag`, `t`, `address`

## Dependencies

- Apache Commons Codec (hex encoding)
- OkHttp (WebSocket connections)
- BouncyCastle (Schnorr signatures, secp256k1)
- Jackson (JSON serialization)
- libphonenumber (phone number normalization for nametags)
- SLF4J (logging)

## Key Features

### NIP-04 Encryption with GZIP Compression

Messages larger than 1KB are automatically compressed with GZIP before encryption, reducing token transfer sizes by ~70%.

### Android Compatible

- Uses legacy Apache Commons Codec API for Android framework compatibility
- Pure Java crypto (BouncyCastle) - no native dependencies
- Targets Android API 31+

### Thread Safety

- All public methods return `CompletableFuture` for async operations
- Internal relay connections are managed thread-safely
- Event listeners are called on background threads

## Testing

### Unit Tests

Unit tests run automatically during build:

```bash
./gradlew build
```

### E2E Tests

E2E tests run against a real Nostr relay:

```bash
# Run NIP-17 private messaging E2E tests
./gradlew e2eTest --tests "NIP17E2ETest"

# Use a custom relay
./gradlew e2eTest --tests "NIP17E2ETest" \
    -DnostrRelay=wss://your-relay.com
```

### Payment Request E2E Tests (Manual)

Payment request E2E tests require manual wallet interaction:

```bash
# Send a single payment request
./gradlew e2eTest --tests "PaymentRequestE2ETest.testSendPaymentRequest" \
    -DtargetNametag=mpu-1

# Send multiple payment requests (for UI testing)
./gradlew e2eTest --tests "PaymentRequestE2ETest.testSendMultiplePaymentRequests" \
    -DtargetNametag=mpu-1

# Full flow with token transfer verification (requires wallet interaction)
./gradlew e2eTest --tests "PaymentRequestE2ETest.testFullPaymentRequestFlow" \
    -DtargetNametag=mpu-1 \
    -Damount=1000000
```

## Notes

- Uses `Hex.encodeHex()` (legacy API) instead of `Hex.encodeHexString()` for Android compatibility
- WebSocket EOFException during disconnect is normal and logged at DEBUG level
- All crypto operations use BouncyCastle (pure Java)
- Phone numbers in nametags are normalized using libphonenumber before hashing

## License

MIT License

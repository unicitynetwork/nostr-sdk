# Unicity Nostr SDK

Java SDK for Nostr protocol integration with Unicity blockchain applications.

## Features

- **Token Transfers**: Send and receive Unicity tokens via Nostr encrypted messages
- **Payment Requests**: Request payments from other users via encrypted Nostr messages
- **Nametag Bindings**: Map Unicity nametags to Nostr public keys for discovery
- **Encrypted Messaging**: NIP-04 encrypted direct messages with automatic compression
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
    implementation("org.unicitylabs:nostr-sdk:0.0.3")
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
    <version>0.0.3</version>
</dependency>
```

### Local Development

For local development, publish to mavenLocal:

```bash
./gradlew publishToMavenLocal -Pversion=0.0.3
```

Then use:

```gradle
repositories {
    mavenLocal()
}

dependencies {
    implementation("org.unicitylabs:nostr-sdk:0.0.3")
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

### Send Encrypted Message

```java
String recipientPubkey = "...";
String message = "Hello, Nostr!";

client.publishEncryptedMessage(recipientPubkey, message)
    .thenAccept(eventId -> {
        System.out.println("Message sent: " + eventId);
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
| `org.unicitylabs.nostr.crypto` | Cryptographic operations (Schnorr, NIP-04, Bech32) |
| `org.unicitylabs.nostr.nametag` | Nametag binding protocol with privacy-preserving hashing |
| `org.unicitylabs.nostr.token` | Token transfer protocol with compression |
| `org.unicitylabs.nostr.payment` | Payment request protocol |

## Event Kinds

| Kind | Name | Description |
|------|------|-------------|
| 0 | PROFILE | User profile metadata (NIP-01) |
| 1 | TEXT_NOTE | Plain text note (NIP-01) |
| 4 | ENCRYPTED_DM | Encrypted direct message (NIP-04) |
| 30078 | APP_DATA | Nametag binding (parameterized replaceable) |
| 31111 | AGENT_PROFILE | Agent profile information |
| 31112 | AGENT_LOCATION | Agent GPS location broadcast |
| 31113 | TOKEN_TRANSFER | Unicity token transfer |
| 31114 | FILE_METADATA | File metadata for large transfers |
| 31115 | PAYMENT_REQUEST | Payment request |

## Protocol Details

### Token Transfer Protocol

- **Prefix**: `token_transfer:`
- **Event Kind**: 31113
- **Encryption**: NIP-04
- **Compression**: GZIP (auto for payloads > 1KB)
- **Content**: `token_transfer:{sourceToken, transferTx}`

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

### E2E Tests (Manual)

E2E tests require manual interaction and are excluded from normal builds. Run them explicitly:

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

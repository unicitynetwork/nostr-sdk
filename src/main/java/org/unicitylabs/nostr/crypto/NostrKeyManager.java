package org.unicitylabs.nostr.crypto;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Nostr key management for signing, encryption, and key encoding.
 * Provides a high-level API for all cryptographic operations.
 */
public class NostrKeyManager {

    private final byte[] privateKey;
    private final byte[] publicKey;
    private final String publicKeyHex;

    /**
     * Create key manager from existing private key.
     *
     * @param privateKey 32-byte private key
     */
    private NostrKeyManager(byte[] privateKey) {
        if (privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }
        this.privateKey = Arrays.copyOf(privateKey, 32);
        this.publicKey = SchnorrSigner.getPublicKey(privateKey);
        // Use legacy API for Android compatibility (old commons-codec in system framework)
        this.publicKeyHex = new String(Hex.encodeHex(publicKey));
    }

    /**
     * Create key manager from existing private key.
     *
     * @param privateKey 32-byte private key
     * @return NostrKeyManager instance
     */
    public static NostrKeyManager fromPrivateKey(byte[] privateKey) {
        return new NostrKeyManager(privateKey);
    }

    /**
     * Create key manager from hex-encoded private key.
     *
     * @param privateKeyHex Hex-encoded private key
     * @return NostrKeyManager instance
     */
    public static NostrKeyManager fromPrivateKeyHex(String privateKeyHex) {
        try {
            return new NostrKeyManager(Hex.decodeHex(privateKeyHex.toCharArray()));
        } catch (DecoderException e) {
            throw new IllegalArgumentException("Invalid hex string", e);
        }
    }

    /**
     * Create key manager from Bech32-encoded private key (nsec...).
     *
     * @param nsec Bech32-encoded private key
     * @return NostrKeyManager instance
     */
    public static NostrKeyManager fromNsec(String nsec) {
        Bech32.DecodedBech32 decoded = Bech32.decode(nsec);
        if (!decoded.hrp.equals("nsec")) {
            throw new IllegalArgumentException("Invalid nsec format");
        }
        return new NostrKeyManager(decoded.data);
    }

    /**
     * Generate a new random key pair.
     *
     * @return NostrKeyManager instance with new keys
     */
    public static NostrKeyManager generate() {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);
        return new NostrKeyManager(privateKey);
    }

    // Key getters

    /**
     * Get private key as byte array (use with caution!).
     */
    public byte[] getPrivateKey() {
        return Arrays.copyOf(privateKey, 32);
    }

    /**
     * Get private key as hex string.
     */
    public String getPrivateKeyHex() {
        return new String(Hex.encodeHex(privateKey));
    }

    /**
     * Get private key as Bech32 (nsec...).
     */
    public String getNsec() {
        return Bech32.encode("nsec", privateKey);
    }

    /**
     * Get public key as byte array (32 bytes, x-only).
     */
    public byte[] getPublicKey() {
        return Arrays.copyOf(publicKey, 32);
    }

    /**
     * Get public key as hex string.
     */
    public String getPublicKeyHex() {
        return publicKeyHex;
    }

    /**
     * Get public key as Bech32 (npub...).
     */
    public String getNpub() {
        return Bech32.encode("npub", publicKey);
    }

    // Signing operations

    /**
     * Sign a 32-byte hash with Schnorr signature (BIP-340).
     *
     * @param messageHash 32-byte hash to sign
     * @return 64-byte Schnorr signature
     */
    public byte[] sign(byte[] messageHash) throws Exception {
        return SchnorrSigner.sign(messageHash, privateKey);
    }

    /**
     * Sign a 32-byte hash and return hex-encoded signature.
     *
     * @param messageHash 32-byte hash to sign
     * @return Hex-encoded signature
     */
    public String signHex(byte[] messageHash) throws Exception {
        return new String(Hex.encodeHex(sign(messageHash)));
    }

    /**
     * Verify a Schnorr signature.
     *
     * @param signature 64-byte signature
     * @param messageHash 32-byte hash
     * @param publicKey 32-byte x-only public key
     * @return true if signature is valid
     */
    public static boolean verify(byte[] signature, byte[] messageHash, byte[] publicKey) {
        return SchnorrSigner.verify(signature, messageHash, publicKey);
    }

    /**
     * Verify a hex-encoded Schnorr signature.
     *
     * @param signatureHex Hex-encoded signature
     * @param messageHash 32-byte hash
     * @param publicKeyHex Hex-encoded public key
     * @return true if signature is valid
     */
    public static boolean verifyHex(String signatureHex, byte[] messageHash, String publicKeyHex) {
        try {
            byte[] signature = Hex.decodeHex(signatureHex.toCharArray());
            byte[] publicKey = Hex.decodeHex(publicKeyHex.toCharArray());
            return verify(signature, messageHash, publicKey);
        } catch (Exception e) {
            return false;
        }
    }

    // Encryption operations (NIP-04)

    /**
     * Encrypt a message for a recipient using NIP-04.
     * Automatically compresses large messages.
     *
     * @param message Plaintext message
     * @param recipientPublicKey Recipient's 32-byte x-only public key
     * @return Encrypted content
     */
    public String encrypt(String message, byte[] recipientPublicKey) throws Exception {
        return NIP04Encryption.encrypt(message, privateKey, recipientPublicKey);
    }

    /**
     * Encrypt a message for a recipient (hex public key).
     *
     * @param message Plaintext message
     * @param recipientPublicKeyHex Recipient's hex-encoded public key
     * @return Encrypted content
     */
    public String encryptHex(String message, String recipientPublicKeyHex) throws Exception {
        return encrypt(message, Hex.decodeHex(recipientPublicKeyHex.toCharArray()));
    }

    /**
     * Decrypt a NIP-04 encrypted message.
     * Automatically decompresses if needed.
     *
     * @param encryptedContent Encrypted content
     * @param senderPublicKey Sender's 32-byte x-only public key
     * @return Decrypted plaintext message
     */
    public String decrypt(String encryptedContent, byte[] senderPublicKey) throws Exception {
        return NIP04Encryption.decrypt(encryptedContent, privateKey, senderPublicKey);
    }

    /**
     * Decrypt a NIP-04 encrypted message (hex public key).
     *
     * @param encryptedContent Encrypted content
     * @param senderPublicKeyHex Sender's hex-encoded public key
     * @return Decrypted plaintext message
     */
    public String decryptHex(String encryptedContent, String senderPublicKeyHex) throws Exception {
        return decrypt(encryptedContent, Hex.decodeHex(senderPublicKeyHex.toCharArray()));
    }

    /**
     * Derive shared secret with another party using ECDH.
     *
     * @param theirPublicKey Their 32-byte x-only public key
     * @return 32-byte shared secret
     */
    public byte[] deriveSharedSecret(byte[] theirPublicKey) throws Exception {
        return NIP04Encryption.deriveSharedSecret(privateKey, theirPublicKey);
    }

    // Utility methods

    /**
     * Check if a public key matches this key manager's public key.
     */
    public boolean isMyPublicKey(String publicKeyHex) {
        return this.publicKeyHex.equalsIgnoreCase(publicKeyHex);
    }

    /**
     * Clear sensitive data from memory (call when done).
     */
    public void clear() {
        Arrays.fill(privateKey, (byte) 0);
    }

    @Override
    public String toString() {
        return "NostrKeyManager{" +
                "npub=" + getNpub().substring(0, 16) + "..." +
                ", pubkey=" + publicKeyHex.substring(0, 16) + "..." +
                '}';
    }
}

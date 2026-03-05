package org.unicitylabs.nostr.nametag;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests for NametagUtils - mirrors JS nostr-js-sdk nametag.test.ts
 */
public class NametagUtilsTest {

    // =========================================================================
    // normalizeNametag
    // =========================================================================

    @Test
    public void shouldLowercaseUsernames() {
        assertEquals("alice", NametagUtils.normalizeNametag("Alice", "US"));
        assertEquals("bob", NametagUtils.normalizeNametag("BOB", "US"));
        assertEquals("camelcase", NametagUtils.normalizeNametag("CamelCase", "US"));
    }

    @Test
    public void shouldRemoveUnicitySuffix() {
        assertEquals("alice", NametagUtils.normalizeNametag("alice@unicity", "US"));
        assertEquals("alice", NametagUtils.normalizeNametag("Alice@unicity", "US"));
    }

    @Test
    public void shouldNormalizePhoneNumbersToE164() {
        assertEquals("+14155551234", NametagUtils.normalizeNametag("+14155551234", "US"));
        assertEquals("+14155551234", NametagUtils.normalizeNametag("415-555-1234", "US"));
        assertEquals("+14155551234", NametagUtils.normalizeNametag("(415) 555-1234", "US"));
    }

    @Test
    public void shouldTrimWhitespace() {
        assertEquals("alice", NametagUtils.normalizeNametag("  alice  ", "US"));
    }

    // =========================================================================
    // hashNametag
    // =========================================================================

    @Test
    public void shouldProduceConsistentHashes() {
        String hash1 = NametagUtils.hashNametag("alice");
        String hash2 = NametagUtils.hashNametag("alice");
        assertEquals(hash1, hash2);
    }

    @Test
    public void shouldProduce64CharHexHash() {
        String hash = NametagUtils.hashNametag("test");
        assertEquals(64, hash.length());
        assertTrue(hash.matches("^[0-9a-f]+$"));
    }

    @Test
    public void shouldNormalizeBeforeHashing() {
        assertEquals(NametagUtils.hashNametag("Alice"), NametagUtils.hashNametag("alice"));
        assertEquals(NametagUtils.hashNametag("alice@unicity"), NametagUtils.hashNametag("alice"));
    }

    @Test
    public void shouldProduceDifferentHashesForDifferentInputs() {
        assertNotEquals(NametagUtils.hashNametag("alice"), NametagUtils.hashNametag("bob"));
    }

    @Test
    public void shouldHashPhoneNumbersConsistently() {
        assertEquals(
                NametagUtils.hashNametag("+14155551234", "US"),
                NametagUtils.hashNametag("415-555-1234", "US")
        );
    }

    // =========================================================================
    // areSameNametag
    // =========================================================================

    @Test
    public void shouldMatchSameNametagsDifferentCase() {
        assertTrue(NametagUtils.areSameNametag("alice", "Alice", "US"));
        assertTrue(NametagUtils.areSameNametag("BOB", "bob", "US"));
    }

    @Test
    public void shouldMatchNametagsWithUnicitySuffix() {
        assertTrue(NametagUtils.areSameNametag("alice", "alice@unicity", "US"));
    }

    @Test
    public void shouldMatchSamePhoneDifferentFormats() {
        assertTrue(NametagUtils.areSameNametag("+14155551234", "415-555-1234", "US"));
    }

    @Test
    public void shouldNotMatchDifferentNametags() {
        assertFalse(NametagUtils.areSameNametag("alice", "bob", "US"));
    }

    // =========================================================================
    // isPhoneNumber
    // =========================================================================

    @Test
    public void shouldRecognizeValidPhoneNumbers() {
        assertTrue(NametagUtils.isPhoneNumber("+14155551234", "US"));
        assertTrue(NametagUtils.isPhoneNumber("415-555-1234", "US"));
    }

    @Test
    public void shouldRejectInvalidPhoneNumbers() {
        assertFalse(NametagUtils.isPhoneNumber("123", "US"));
        assertFalse(NametagUtils.isPhoneNumber("alice", "US"));
    }

    // =========================================================================
    // isValidNametag
    // =========================================================================

    @Test
    public void shouldAcceptValidLowercaseNametags() {
        assertTrue(NametagUtils.isValidNametag("alice"));
        assertTrue(NametagUtils.isValidNametag("bob_42"));
        assertTrue(NametagUtils.isValidNametag("my-wallet"));
    }

    @Test
    public void shouldAcceptUppercaseInput() {
        assertTrue(NametagUtils.isValidNametag("@Alice"));
        assertTrue(NametagUtils.isValidNametag("BOB"));
    }

    @Test
    public void shouldRejectTooShortNametags() {
        assertFalse(NametagUtils.isValidNametag("ab"));
        assertFalse(NametagUtils.isValidNametag("a"));
    }

    @Test
    public void shouldRejectTooLongNametags() {
        assertFalse(NametagUtils.isValidNametag("aaaaaaaaaaaaaaaaaaaaa")); // 21 chars
    }

    @Test
    public void shouldAcceptBoundaryLengths() {
        assertTrue(NametagUtils.isValidNametag("abc")); // min
        assertTrue(NametagUtils.isValidNametag("aaaaaaaaaaaaaaaaaaaa")); // 20 = max
    }

    @Test
    public void shouldRejectInvalidCharacters() {
        assertFalse(NametagUtils.isValidNametag("hello world"));
        assertFalse(NametagUtils.isValidNametag("a]b"));
        assertFalse(NametagUtils.isValidNametag("foo.bar"));
    }

    @Test
    public void shouldAcceptValidPhoneNumbers() {
        assertTrue(NametagUtils.isValidNametag("+14155552671", "US"));
        assertTrue(NametagUtils.isValidNametag("415-555-2671", "US"));
    }

    @Test
    public void shouldStripUnicitySuffixBeforeValidation() {
        assertTrue(NametagUtils.isValidNametag("alice@unicity"));
    }

    // =========================================================================
    // hashAddressForTag
    // =========================================================================

    @Test
    public void shouldProduceConsistentAddressHashes() {
        String hash1 = NametagUtils.hashAddressForTag("DIRECT://test");
        String hash2 = NametagUtils.hashAddressForTag("DIRECT://test");
        assertEquals(hash1, hash2);
    }

    @Test
    public void shouldProduceAddressHashAs64CharHex() {
        String hash = NametagUtils.hashAddressForTag("alpha1test");
        assertEquals(64, hash.length());
        assertTrue(hash.matches("^[0-9a-f]+$"));
    }

    @Test
    public void shouldProduceDifferentHashesForDifferentAddresses() {
        String hash1 = NametagUtils.hashAddressForTag("DIRECT://a");
        String hash2 = NametagUtils.hashAddressForTag("DIRECT://b");
        assertNotEquals(hash1, hash2);
    }

    // =========================================================================
    // sha256Hex
    // =========================================================================

    @Test
    public void shouldExposePublicSha256Hex() {
        String hash = NametagUtils.sha256Hex("test");
        assertEquals(64, hash.length());
        assertTrue(hash.matches("^[0-9a-f]+$"));
    }

    // =========================================================================
    // encryptNametag / decryptNametag
    // =========================================================================

    @Test
    public void shouldRoundTripEncryptAndDecryptNametag() throws Exception {
        org.unicitylabs.nostr.crypto.NostrKeyManager km = org.unicitylabs.nostr.crypto.NostrKeyManager.generate();
        String encrypted = NametagUtils.encryptNametag("alice", km.getPrivateKeyHex());
        assertNotNull(encrypted);
        assertTrue(encrypted.length() > 0);

        String decrypted = NametagUtils.decryptNametag(encrypted, km.getPrivateKeyHex());
        assertEquals("alice", decrypted);
    }

    @Test
    public void shouldReturnNullWhenDecryptingWithWrongKey() throws Exception {
        org.unicitylabs.nostr.crypto.NostrKeyManager km1 = org.unicitylabs.nostr.crypto.NostrKeyManager.generate();
        org.unicitylabs.nostr.crypto.NostrKeyManager km2 = org.unicitylabs.nostr.crypto.NostrKeyManager.generate();
        String encrypted = NametagUtils.encryptNametag("alice", km1.getPrivateKeyHex());

        String decrypted = NametagUtils.decryptNametag(encrypted, km2.getPrivateKeyHex());
        assertNull(decrypted);
    }

    @Test
    public void shouldReturnNullForInvalidBase64Input() {
        org.unicitylabs.nostr.crypto.NostrKeyManager km = org.unicitylabs.nostr.crypto.NostrKeyManager.generate();
        String decrypted = NametagUtils.decryptNametag("not-valid-base64!!!", km.getPrivateKeyHex());
        assertNull(decrypted);
    }

    // =========================================================================
    // constants
    // =========================================================================

    @Test
    public void shouldHaveCorrectConstants() {
        assertEquals(3, NametagUtils.NAMETAG_MIN_LENGTH);
        assertEquals(20, NametagUtils.NAMETAG_MAX_LENGTH);
    }

    // =========================================================================
    // formatForDisplay
    // =========================================================================

    @Test
    public void shouldHideMiddleDigitsOfPhoneNumbers() {
        String formatted = NametagUtils.formatForDisplay("+14155551234", "US");
        assertTrue(formatted.contains("***"));
    }

    @Test
    public void shouldReturnNormalizedUsernameForNonPhone() {
        assertEquals("alice", NametagUtils.formatForDisplay("Alice", "US"));
        assertEquals("bob", NametagUtils.formatForDisplay("bob@unicity", "US"));
    }
}

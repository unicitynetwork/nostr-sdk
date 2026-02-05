package org.unicitylabs.nostr.nametag;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests for NametagUtils — normalization, hashing, and phone number handling.
 */
public class NametagUtilsTest {

    // --- normalizeNametag: Text Nametags ---

    @Test
    public void testNormalizeLowercase() {
        assertEquals("alice", NametagUtils.normalizeNametag("Alice", "US"));
    }

    @Test
    public void testNormalizeAlreadyLowercase() {
        assertEquals("alice", NametagUtils.normalizeNametag("alice", "US"));
    }

    @Test
    public void testNormalizeRemoveAtUnicitySuffix() {
        assertEquals("alice", NametagUtils.normalizeNametag("alice@unicity", "US"));
    }

    @Test
    public void testNormalizeRemoveAtUnicityCaseInsensitive() {
        assertEquals("bob", NametagUtils.normalizeNametag("Bob@UNICITY", "US"));
    }

    @Test
    public void testNormalizeTrimWhitespace() {
        assertEquals("alice", NametagUtils.normalizeNametag("  alice  ", "US"));
    }

    @Test
    public void testNormalizeEmptyString() {
        String result = NametagUtils.normalizeNametag("", "US");
        assertEquals("", result);
    }

    @Test
    public void testNormalizeWhitespaceOnly() {
        String result = NametagUtils.normalizeNametag("   ", "US");
        assertEquals("", result);
    }

    @Test
    public void testNormalizeMixedCase() {
        assertEquals("testuser123", NametagUtils.normalizeNametag("TestUser123", "US"));
    }

    // --- normalizeNametag: Phone Numbers ---

    @Test
    public void testNormalizeUSPhoneWithCountryCode() {
        assertEquals("+14155552671", NametagUtils.normalizeNametag("+14155552671", "US"));
    }

    @Test
    public void testNormalizeUSPhoneWithoutCountryCode() {
        assertEquals("+14155552671", NametagUtils.normalizeNametag("4155552671", "US"));
    }

    @Test
    public void testNormalizeUSPhoneWithFormatting() {
        assertEquals("+14155552671", NametagUtils.normalizeNametag("(415) 555-2671", "US"));
    }

    @Test
    public void testNormalizeUSPhoneWithDashes() {
        assertEquals("+14155552671", NametagUtils.normalizeNametag("415-555-2671", "US"));
    }

    @Test
    public void testNormalizeInternationalPhoneUK() {
        assertEquals("+447911123456", NametagUtils.normalizeNametag("+447911123456", "GB"));
    }

    @Test
    public void testNormalizePlusSignAlwaysTreatedAsPhone() {
        // Starts with "+" → always treated as phone number
        String result = NametagUtils.normalizeNametag("+14155552671", "US");
        assertTrue(result.startsWith("+"));
    }

    @Test
    public void testNormalizeShortDigitStringNotPhone() {
        // 6 digits < minimum of 7 for phone detection → treated as text nametag
        String result = NametagUtils.normalizeNametag("123456", "US");
        assertEquals("123456", result);
    }

    // --- hashNametag ---

    @Test
    public void testHashIsDeterministic() {
        String hash1 = NametagUtils.hashNametag("alice", "US");
        String hash2 = NametagUtils.hashNametag("alice", "US");
        assertEquals(hash1, hash2);
    }

    @Test
    public void testHashIs64CharHex() {
        String hash = NametagUtils.hashNametag("alice");
        assertEquals(64, hash.length());
        assertTrue(hash.matches("[0-9a-f]{64}"));
    }

    @Test
    public void testHashNormalizesBeforeHashing() {
        String hash1 = NametagUtils.hashNametag("Alice@UNICITY", "US");
        String hash2 = NametagUtils.hashNametag("alice", "US");
        assertEquals(hash1, hash2);
    }

    @Test
    public void testDifferentNametagsProduceDifferentHashes() {
        String hashAlice = NametagUtils.hashNametag("alice");
        String hashBob = NametagUtils.hashNametag("bob");
        assertNotEquals(hashAlice, hashBob);
    }

    @Test
    public void testHashDefaultCountryIsUS() {
        String hash1 = NametagUtils.hashNametag("alice");
        String hash2 = NametagUtils.hashNametag("alice", "US");
        assertEquals(hash1, hash2);
    }

    @Test
    public void testHashPhoneNormalizesBeforeHashing() {
        String hash1 = NametagUtils.hashNametag("+14155552671", "US");
        String hash2 = NametagUtils.hashNametag("(415) 555-2671", "US");
        assertEquals(hash1, hash2);
    }

    // --- areSameNametag ---

    @Test
    public void testAreSameNametagDifferentCase() {
        assertTrue(NametagUtils.areSameNametag("Alice", "alice", "US"));
    }

    @Test
    public void testAreSameNametagWithAndWithoutSuffix() {
        assertTrue(NametagUtils.areSameNametag("alice", "alice@unicity", "US"));
    }

    @Test
    public void testAreSameNametagPhoneDifferentFormats() {
        assertTrue(NametagUtils.areSameNametag("+14155552671", "(415) 555-2671", "US"));
    }

    @Test
    public void testAreSameNametagDifferentNametags() {
        assertFalse(NametagUtils.areSameNametag("alice", "bob", "US"));
    }

    @Test
    public void testAreSameNametagTrimming() {
        assertTrue(NametagUtils.areSameNametag("  alice  ", "alice", "US"));
    }

    // --- formatForDisplay ---

    @Test
    public void testFormatForDisplayPhoneMasked() {
        String result = NametagUtils.formatForDisplay("+14155552671", "US");
        // Should mask middle digits: +1415***2671
        assertTrue(result.contains("***"));
        assertTrue(result.startsWith("+1415"));
        assertTrue(result.endsWith("2671"));
    }

    @Test
    public void testFormatForDisplayTextNametagNotMasked() {
        String result = NametagUtils.formatForDisplay("alice", "US");
        assertEquals("alice", result);
    }

    @Test
    public void testFormatForDisplayPhoneWithFormatting() {
        String result = NametagUtils.formatForDisplay("(415) 555-2671", "US");
        assertTrue(result.contains("***"));
    }

    // --- Phone Detection Heuristic ---

    @Test
    public void testPhoneDetectionStartsWithPlus() {
        // "+anything" is always treated as phone
        String result = NametagUtils.normalizeNametag("+1234", "US");
        // Even if it fails phone parsing, digits are extracted
        assertNotNull(result);
    }

    @Test
    public void testPhoneDetectionMajorityDigits() {
        // 10 digits out of 13 chars = 76% > 50%, and >= 7 digits
        String result = NametagUtils.normalizeNametag("abc1234567890", "US");
        // This should be treated as phone-like (majority digits)
        assertNotNull(result);
    }

    @Test
    public void testPhoneDetectionMinorityDigitsIsFalse() {
        // "alice123" = 3 digits out of 8 = 37.5% < 50%
        // Should be treated as text nametag → lowercase
        assertEquals("alice123", NametagUtils.normalizeNametag("Alice123", "US"));
    }

    @Test
    public void testPhoneDetectionExactlySevenDigits() {
        // 7 digits, 0 other chars → 100% > 50% and >= 7 → phone
        String result = NametagUtils.normalizeNametag("1234567", "US");
        // Should attempt phone normalization
        assertNotNull(result);
    }

    @Test
    public void testPhoneDetectionSixDigitsNotPhone() {
        // 6 digits < 7 minimum → not phone → treated as text
        assertEquals("123456", NametagUtils.normalizeNametag("123456", "US"));
    }
}

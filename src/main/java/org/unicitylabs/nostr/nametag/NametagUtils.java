package org.unicitylabs.nostr.nametag;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * Utility class for deterministic nametag hashing.
 * This ensures privacy and allows phone numbers to be used as nametags.
 *
 * Examples:
 * - Regular nametag: "alice" → hash("unicity:nametag:alice")
 * - Phone as nametag: "+14155552671" → hash("unicity:nametag:+14155552671")
 *
 * This way phone numbers can BE nametags naturally!
 */
public class NametagUtils {

    private static final String NAMETAG_SALT = "unicity:nametag:";
    private static final PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();

    /**
     * Hash a nametag for privacy-preserving storage on Nostr.
     * Works for both regular nametags and phone numbers.
     *
     * @param nametag The nametag string (e.g., "alice" or "+14155552671")
     * @param defaultCountry Default country code for phone normalization (e.g., "US")
     * @return Hex-encoded SHA-256 hash of the nametag
     */
    public static String hashNametag(String nametag, String defaultCountry) {
        // Normalize the nametag
        String normalized = normalizeNametag(nametag, defaultCountry);

        // Hash with salt
        String input = NAMETAG_SALT + normalized;
        return sha256(input);
    }

    /**
     * Hash a nametag with default country "US".
     */
    public static String hashNametag(String nametag) {
        return hashNametag(nametag, "US");
    }

    /**
     * Normalize a nametag before hashing.
     * - If it looks like a phone number, normalize to E.164
     * - Otherwise, lowercase and trim
     *
     * @param nametag The raw nametag
     * @param defaultCountry Default country for phone normalization
     * @return Normalized nametag
     */
    public static String normalizeNametag(String nametag, String defaultCountry) {
        String trimmed = nametag.trim();

        // Check if it looks like a phone number
        if (isLikelyPhoneNumber(trimmed)) {
            // Try to normalize as phone
            String normalized = normalizePhoneNumber(trimmed, defaultCountry);
            if (normalized != null) {
                return normalized;
            }
            // If normalization failed, just clean digits
            StringBuilder cleaned = new StringBuilder();
            for (char c : trimmed.toCharArray()) {
                if (Character.isDigit(c) || c == '+') {
                    cleaned.append(c);
                }
            }
            return cleaned.toString();
        }

        // For regular nametags: lowercase, remove @unicity suffix
        String lower = trimmed.toLowerCase(Locale.ROOT);
        if (lower.endsWith("@unicity")) {
            return lower.substring(0, lower.length() - 8);
        }
        return lower;
    }

    /**
     * Normalize a phone number to E.164 format.
     *
     * @param phoneNumber Phone number in any format
     * @param defaultCountry Default country code (e.g., "US")
     * @return E.164 formatted phone number or null if invalid
     */
    private static String normalizePhoneNumber(String phoneNumber, String defaultCountry) {
        String cleaned = phoneNumber.trim();
        if (cleaned.isEmpty()) {
            return null;
        }

        try {
            Phonenumber.PhoneNumber parsedNumber;
            if (cleaned.startsWith("+")) {
                // Already has country code
                parsedNumber = phoneUtil.parse(cleaned, null);
            } else {
                // Use default country for local numbers
                parsedNumber = phoneUtil.parse(cleaned, defaultCountry);
            }

            // Validate the parsed number
            if (!phoneUtil.isValidNumber(parsedNumber)) {
                return null;
            }

            // Format to E.164 (e.g., +14155552671)
            return phoneUtil.format(parsedNumber, PhoneNumberUtil.PhoneNumberFormat.E164);
        } catch (NumberParseException e) {
            // Invalid phone number format
            return null;
        }
    }

    /**
     * Check if a string looks like a phone number.
     * Simple heuristic: starts with + or has >50% digits
     */
    private static boolean isLikelyPhoneNumber(String str) {
        if (str.startsWith("+")) {
            return true;
        }

        int digitCount = 0;
        for (char c : str.toCharArray()) {
            if (Character.isDigit(c)) {
                digitCount++;
            }
        }

        int totalCount = str.length();
        // More than 50% digits and at least 7 digits total
        return digitCount >= 7 && (float) digitCount / totalCount > 0.5f;
    }

    /**
     * Compute SHA-256 hash of a string.
     *
     * @param input Input string
     * @return Hex-encoded hash
     */
    private static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder hex = new StringBuilder();
            for (byte b : hashBytes) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Check if two nametags resolve to the same hash.
     * Useful for comparing different formats of the same identifier.
     *
     * @param tag1 First nametag
     * @param tag2 Second nametag
     * @param defaultCountry Default country code
     * @return true if both hash to the same value
     */
    public static boolean areSameNametag(String tag1, String tag2, String defaultCountry) {
        return hashNametag(tag1, defaultCountry).equals(hashNametag(tag2, defaultCountry));
    }

    /**
     * Format a nametag for display purposes.
     * Hides middle digits for phone numbers.
     *
     * @param nametag The nametag
     * @param defaultCountry Default country code
     * @return Display-friendly version
     */
    public static String formatForDisplay(String nametag, String defaultCountry) {
        String normalized = normalizeNametag(nametag, defaultCountry);

        // Check if it's a phone number
        if (isLikelyPhoneNumber(normalized)) {
            // Hide middle digits: +1415***2671
            if (normalized.length() >= 10) {
                String start = normalized.substring(0, 5);
                String end = normalized.substring(normalized.length() - 4);
                return start + "***" + end;
            }
        }

        // Regular nametag - return as-is
        return nametag;
    }
}
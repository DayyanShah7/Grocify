package com.dayyan.firstapp.model.security

import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import com.dayyan.firstapp.model.service.module.EncryptedPrefs
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Manages the lifecycle of the database encryption passphrase.
 *
 * Generates a cryptographically secure 256-bit passphrase on first launch,
 * persists it in Android Keystore-backed [EncryptedSharedPreferences],
 * and provides a way to wipe it from memory after use.
 *
 * Note: This class should be used as the passphrase source when opening
 * the Room database via [SupportFactory]. Using a hardcoded or static
 * passphrase instead defeats the purpose of encryption as it can be
 * extracted from the APK.
 *
 * Known limitation: The Base64-encoded passphrase is stored and retrieved
 * as a Java [String], which is immutable and cannot be zeroed from memory.
 * This is a fundamental limitation of [EncryptedSharedPreferences] and is
 * accepted as a known trade-off.
 */
@Singleton
class DatabasePassphraseManager @Inject constructor(
    @EncryptedPrefs private val prefs: SharedPreferences
) {

    private val secureRandom = SecureRandom()

    private companion object {
        const val KEY_PASSPHRASE = "db_passphrase"
        // 32 bytes = 256-bit passphrase passed to SQLCipher as raw key material
        const val PASSPHRASE_BYTE_LENGTH = 32
    }

    /**
     * Returns the existing passphrase if one has been generated before,
     * or generates and persists a new one on first launch.
     *
     * The returned [ByteArray] should be wiped after use by calling [wipe]
     * to prevent the key from lingering in memory longer than necessary.
     */
    @Synchronized
    fun getOrCreatePassphrase(): ByteArray {
        val existing = try {
            prefs.getString(KEY_PASSPHRASE, null)
        } catch (e: SecurityException) {
            throw IllegalStateException("Passphrase store is corrupted or tampered.", e)
        }

        if (existing != null) return Base64.decode(existing, Base64.NO_WRAP)

        val passphrase = ByteArray(PASSPHRASE_BYTE_LENGTH).also { secureRandom.nextBytes(it) }

        // commit() is intentional — we must confirm the write succeeded
        // before returning the passphrase to prevent key loss on crash
        val written = prefs.edit()
            .putString(KEY_PASSPHRASE, Base64.encodeToString(passphrase, Base64.NO_WRAP))
            .commit()

        if (!written) {
            wipe(passphrase)
            throw IllegalStateException("Failed to persist database passphrase — aborting to prevent data loss.")
        }

        // Return a copy and wipe the original so the internal reference
        // and the caller's reference are fully separate
        return passphrase.copyOf().also { wipe(passphrase) }
    }

    /**
     * Zeroes out the passphrase bytes in memory after use.
     * Prevents the key from lingering in the heap and appearing in
     * heap dumps or memory forensics.
     *
     * Should be called in a `finally` block to guarantee execution.
     */
    fun wipe(passphrase: ByteArray) = passphrase.fill(0)
}
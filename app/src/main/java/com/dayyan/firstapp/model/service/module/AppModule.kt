@file:Suppress("unused")

package com.dayyan.firstapp.model.service.module

import android.content.Context
import android.content.SharedPreferences
import androidx.credentials.CredentialManager
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.dayyan.firstapp.model.service.AccountService
import com.dayyan.firstapp.model.service.impl.AccountServiceImpl
import com.google.firebase.auth.FirebaseAuth
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.io.IOException
import java.security.GeneralSecurityException
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class AppModule {

    // ── @Binds ─────────────────────────────────────────────────────────────────

    @Binds
    @Singleton
    abstract fun bindAccountService(impl: AccountServiceImpl): AccountService

    // ── @Provides ──────────────────────────────────────────────────────────────

    companion object {

        @Provides
        @Singleton
        fun provideFirebaseAuth(): FirebaseAuth = FirebaseAuth.getInstance()

        /**
         * Provides a singleton [CredentialManager] built with [ApplicationContext].
         *
         * Using the application context (not an Activity) guarantees the singleton
         * service never holds a reference to a short-lived Activity, preventing
         * memory leaks. [CredentialManager.clearCredentialState] — the only call
         * made from singleton services — does not require an Activity context.
         *
         * Note: [CredentialManager.getCredential] (used in Google Sign-In) still
         * receives an Activity at call-time for its UI overlay; that Activity
         * reference is not stored anywhere.
         */
        @Provides
        @Singleton
        fun provideCredentialManager(
            @ApplicationContext context: Context,
        ): CredentialManager = CredentialManager.create(context)

        /**
         * Provides an application-scoped [CoroutineScope] for use in singleton services.
         *
         * Backed by [SupervisorJob] so a failing child coroutine does not cancel siblings,
         * and by [Dispatchers.Default] as the base dispatcher (individual launches can
         * switch to [Dispatchers.IO] if needed). This scope is never cancelled during
         * normal app operation — it lives for the entire process lifetime.
         *
         * Do **not** use this for work that should be scoped to a screen or ViewModel;
         * use `viewModelScope` for that instead.
         */
        @Provides
        @Singleton
        @ApplicationScope
        fun provideApplicationScope(): CoroutineScope =
            CoroutineScope(SupervisorJob() + Dispatchers.Default)

        /**
         * Provides the [EncryptedSharedPreferences] instance that backs
         * [com.dayyan.firstapp.model.security.DatabasePassphraseManager].
         *
         * Separated from [DatabasePassphraseManager] so that tests can inject
         * a fake [SharedPreferences] without touching the AndroidKeyStore,
         * making all branches of [DatabasePassphraseManager] testable.
         *
         * Error handling:
         * - [GeneralSecurityException] — KeyStore key invalidated (e.g. screen lock
         *   change on some devices). Clears corrupted prefs so the app can recover
         *   on next launch instead of being permanently bricked.
         * - [IOException] — filesystem-level failure reading/writing the prefs file.
         */
        @Provides
        @Singleton
        @EncryptedPrefs
        fun provideEncryptedPrefs(
            @ApplicationContext context: Context
        ): SharedPreferences {
            return try {
                val masterKey = MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build()

                EncryptedSharedPreferences.create(
                    context,
                    PREF_FILE,
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                )
            } catch (e: GeneralSecurityException) {
                // Keystore key may have been invalidated — clear corrupted prefs
                // so the app can recover on next launch instead of being permanently bricked
                context.deleteSharedPreferences(PREF_FILE)
                throw IllegalStateException("Keystore error — prefs cleared, please restart the app.", e)
            } catch (e: IOException) {
                throw IllegalStateException("Failed to initialize encrypted preferences — IO error.", e)
            }
        }

        private const val PREF_FILE = "secure_db_prefs"
    }
}
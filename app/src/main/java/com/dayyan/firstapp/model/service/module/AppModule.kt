@file:Suppress("unused")

package com.dayyan.firstapp.model.service.module

import android.content.Context
import androidx.credentials.CredentialManager
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
    }
}
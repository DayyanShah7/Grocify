package com.dayyan.firstapp.model.service.module

import javax.inject.Qualifier

/**
 * Hilt qualifier for the [androidx.security.crypto.EncryptedSharedPreferences]
 * instance that backs [com.dayyan.firstapp.model.security.DatabasePassphraseManager].
 *
 * Using a qualifier prevents Hilt from confusing this [android.content.SharedPreferences]
 * binding with any other [android.content.SharedPreferences] binding in the graph.
 *
 * Usage:
 * ```kotlin
 * class DatabasePassphraseManager @Inject constructor(
 *     @EncryptedPrefs private val prefs: SharedPreferences
 * )
 * ```
 */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class EncryptedPrefs
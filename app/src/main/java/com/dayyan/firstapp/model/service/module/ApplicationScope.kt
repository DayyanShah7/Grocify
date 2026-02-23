package com.dayyan.firstapp.model.service.module

import javax.inject.Qualifier

/**
 * Hilt qualifier for a [kotlinx.coroutines.CoroutineScope] that lives for the
 * entire application process. Provided by [AppModule] and backed by
 * [kotlinx.coroutines.SupervisorJob] + [kotlinx.coroutines.Dispatchers.Default].
 *
 * Inject this into singleton services that need to launch coroutines from
 * non-suspending callbacks (e.g. Firebase phone-auth callbacks), so the
 * launched work has a proper structured lifecycle instead of being an
 * orphaned [kotlinx.coroutines.CoroutineScope] with no parent [kotlinx.coroutines.Job].
 *
 * Usage:
 * ```kotlin
 * class AccountServiceImpl @Inject constructor(
 *     @ApplicationScope private val applicationScope: CoroutineScope
 * )
 * ```
 */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class ApplicationScope
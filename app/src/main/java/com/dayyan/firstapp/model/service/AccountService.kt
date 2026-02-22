package com.dayyan.firstapp.model.service

import android.app.Activity
import com.dayyan.firstapp.model.AuthResult
import com.dayyan.firstapp.model.MfaCodeResult
import com.dayyan.firstapp.model.User
import com.google.firebase.auth.MultiFactorResolver

interface AccountService {

    fun isUserAuthenticated(): Boolean

    fun getCurrentUserId(): String?

    suspend fun signUpWithEmail(email: String, password: String): AuthResult<User>

    suspend fun signInWithEmail(email: String, password: String): AuthResult<Unit>

    suspend fun signInWithGoogle(activity: Activity): AuthResult<User>

    suspend fun signOut(): AuthResult<Unit>

    suspend fun deleteAccount(): AuthResult<Unit>

    suspend fun sendPasswordResetEmail(email: String): AuthResult<Unit>

    fun isUserMfaEnabled(): Boolean?

    suspend fun checkUserEmailVerificationStatus(): AuthResult<Boolean>

    suspend fun sendVerificationEmail(): AuthResult<Unit>

    suspend fun resendVerificationEmail(): AuthResult<Unit>

    suspend fun sendMfaCodeForMfaEnabling(phoneNumber: String, activity: Activity): AuthResult<MfaCodeResult>

    suspend fun enableMfa(verificationId: String, code: String): AuthResult<Unit>

    suspend fun disableMfa(): AuthResult<Unit>

    suspend fun sendMfaCodeForSignIn(resolver: MultiFactorResolver, activity: Activity): AuthResult<MfaCodeResult>

    suspend fun verifyMfaCodeForSignIn(resolver: MultiFactorResolver, verificationId: String, code: String): AuthResult<Unit>
}
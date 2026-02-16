package com.dayyan.firstapp.model.service.impl

import android.app.Activity
import android.content.Context
import android.util.Log
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import com.dayyan.firstapp.R
import com.dayyan.firstapp.model.AuthResult
import com.dayyan.firstapp.model.User
import com.dayyan.firstapp.model.service.AccountService
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException
import com.google.firebase.FirebaseNetworkException
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseAuthException
import com.google.firebase.auth.FirebaseAuthInvalidCredentialsException
import com.google.firebase.auth.FirebaseAuthInvalidUserException
import com.google.firebase.auth.FirebaseAuthMultiFactorException
import com.google.firebase.auth.FirebaseAuthRecentLoginRequiredException
import com.google.firebase.auth.FirebaseAuthUserCollisionException
import com.google.firebase.auth.FirebaseAuthWeakPasswordException
import com.google.firebase.auth.GoogleAuthProvider
import kotlinx.coroutines.tasks.await
import java.security.MessageDigest
import java.util.UUID
import javax.inject.Inject

class AccountServiceImpl @Inject constructor(
    private val firebaseAuth: FirebaseAuth
): AccountService {

    override fun isUserAuthenticated(): Boolean {
        val isAuthenticated = firebaseAuth.currentUser != null
        Log.d(TAG, "User authenticated: $isAuthenticated")
        return isAuthenticated
    }

    override fun getCurrentUserId(): String? {
        val userId = firebaseAuth.currentUser?.uid
        Log.d(TAG, "Current user ID: ${userId ?: "null (not authenticated)"}")
        return userId
    }

    override suspend fun signUpWithEmail(email: String, password: String): AuthResult<User> {
        return try {
            val sanitizedEmail = email.trim().lowercase()

            if (!isValidEmail(sanitizedEmail)) {
                Log.w(TAG, "Sign up failed: Invalid email format")
                return AuthResult.Error("Please enter a valid email address")
            }

            validatePassword(password)?.let { errorMessage ->
                Log.w(TAG, "Sign up failed: $errorMessage")
                return AuthResult.Error(errorMessage)
            }

            val authResult = firebaseAuth.createUserWithEmailAndPassword(sanitizedEmail, password).await()

            val user = authResult.user
            if (user == null) {
                Log.e(TAG, "Sign up succeeded but user is null")
                return AuthResult.Error("Failed to retrieve user information")
            }

            val userInfo = User(
                userId = user.uid,
                email = user.email ?: sanitizedEmail
            )

            Log.d(TAG, "User signed up successfully with email: $sanitizedEmail")
            AuthResult.Success(userInfo)

        } catch (e: FirebaseAuthUserCollisionException) {
            Log.w(TAG, "Sign up failed: Email already exists", e)
            AuthResult.Error("This email is already registered. Try signing in instead.")

        } catch (e: FirebaseAuthWeakPasswordException) {
            Log.w(TAG, "Sign up failed: Weak password", e)
            AuthResult.Error(e.message ?: "Password must be at least 6 characters long")

        } catch (e: FirebaseAuthInvalidCredentialsException) {
            Log.w(TAG, "Sign up failed: Invalid credentials", e)
            AuthResult.Error("Invalid credentials. Please try again")

        } catch (e: FirebaseNetworkException) {
            Log.e(TAG, "Sign up failed: Network Error", e)
            AuthResult.Error("Network error. Please check your internet connection")

        } catch (e: Exception) {
            Log.e(TAG, "Sign up failed: Unexpected Error", e)
            AuthResult.Error("Something went wrong. Please try again later")
        }
    }

    override suspend fun signInWithEmail(email: String, password: String): AuthResult<Unit> {
        return try {
            val sanitizedEmail = email.trim().lowercase()

            if (!isValidEmail(sanitizedEmail)) {
                Log.w(TAG, "Sign in failed: Invalid email format")
                return AuthResult.Error("Please enter a valid email address")
            }

            if (password.isBlank()) {
                Log.w(TAG, "Sign in failed: Empty password")
                return AuthResult.Error("Password cannot be empty")
            }

            firebaseAuth.signInWithEmailAndPassword(sanitizedEmail, password).await()

            Log.d(TAG, "User signed in successfully with email: $sanitizedEmail")
            AuthResult.Success(Unit)

        } catch (e: FirebaseAuthMultiFactorException) {
            Log.w(TAG, "MFA required", e)
            AuthResult.MfaRequired(e.resolver)

        } catch (e: FirebaseAuthInvalidCredentialsException) {
            Log.w(TAG, "Sign in failed: Invalid credentials", e)
            AuthResult.Error("Invalid email or password")

        } catch (e: FirebaseAuthInvalidUserException) {
            Log.w(TAG, "Sign in failed: User not found", e)
            AuthResult.Error("No account found with this email")

        } catch (e: FirebaseNetworkException) {
            Log.e(TAG, "Sign in failed: Network error", e)
            AuthResult.Error("Network error. Please check your internet connection")

        } catch (e: Exception) {
            Log.e(TAG, "Sign in failed: Unexpected error", e)
            AuthResult.Error("Something went wrong. Please try again later")
        }
    }

    override suspend fun signInWithGoogle(activity: Activity): AuthResult<User> {
        return try {
            val webClientId = activity.getString(R.string.default_web_client_id)
            val idToken = getGoogleIdToken(activity, webClientId)

            signInWithGoogleIdToken(idToken)

        } catch (e: GetCredentialCancellationException) {
            Log.e(TAG, "Google sign-in cancelled by user", e)
            AuthResult.Error("Sign in cancelled")

        } catch (e: GetCredentialException) {
            Log.e(TAG, "Failed to get Google credentials", e)
            AuthResult.Error("Failed to sign in with Google. Please try again")

        } catch (e: GoogleIdTokenParsingException) {
            Log.e(TAG, "Failed to parse Google ID token", e)
            AuthResult.Error("Failed to process Google credentials. Please try again")

        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error during Google sign-in", e)
            AuthResult.Error("Something went wrong. Please try again later")
        }
    }

    private suspend fun getGoogleIdToken(
        activity: Activity,
        webClientId: String
    ): String {
        val credentialManager = CredentialManager.create(activity)

        val nonce = generateNonce()

        val googleIdOption = GetGoogleIdOption.Builder()
            .setFilterByAuthorizedAccounts(false)
            .setServerClientId(webClientId)
            .setNonce(nonce)
            .setAutoSelectEnabled(true)
            .build()

        val request = GetCredentialRequest.Builder()
            .addCredentialOption(googleIdOption)
            .build()

        val result = credentialManager.getCredential(
            context = activity,
            request = request
        )

        return extractIdTokenFromCredential(result)
    }

    private fun extractIdTokenFromCredential(result: GetCredentialResponse): String {
        val credential = result.credential

        if (credential is CustomCredential &&
            credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
        ) {
            val googleIdTokenCredential = GoogleIdTokenCredential.createFrom(credential.data)
            return googleIdTokenCredential.idToken
        }

        throw IllegalStateException("Unexpected credential type: ${credential.type}")
    }

    /**
     * Generates a cryptographically secure nonce for Google Sign-In.
     * Uses SHA-256 hashing to prevent replay attacks.
     */
    private fun generateNonce(): String {
        val ranNonce = UUID.randomUUID().toString()
        val bytes = ranNonce.toByteArray()
        val md = MessageDigest.getInstance(SHA_256_ALGORITHM)
        val digest = md.digest(bytes)
        return digest.fold("") { str, it -> str + HEX_FORMAT.format(it) }
    }

    private suspend fun signInWithGoogleIdToken(idToken: String): AuthResult<User> {
        return try {
            val credential = GoogleAuthProvider.getCredential(idToken, null)
            val authResult = firebaseAuth.signInWithCredential(credential).await()

            val user = authResult.user
            if (user == null) {
                Log.e(TAG, "Google sign-in succeeded but user is null")
                return AuthResult.Error("Failed to retrieve user information")
            }

            val email = user.email
            if (email.isNullOrBlank()) {
                Log.e(TAG, "Google sign-in succeeded but email is null or empty")
                return AuthResult.Error("Google account has no email address. Please use a different account.")
            }

            val userInfo = User(
                userId = user.uid,
                email = email
            )

            Log.d(TAG, "User signed in successfully with Google")
            AuthResult.Success(userInfo)

        } catch (e: FirebaseAuthMultiFactorException) {
            Log.w(TAG, "MFA required for Google sign-in", e)
            AuthResult.MfaRequired(e.resolver)

        } catch (e: FirebaseAuthInvalidCredentialsException) {
            Log.w(TAG, "Google sign-in failed: Invalid credentials", e)
            AuthResult.Error("Invalid Google credentials. Please try again")

        } catch (e: FirebaseNetworkException) {
            Log.e(TAG, "Google sign-in failed: Network error", e)
            AuthResult.Error("Network error. Please check your internet connection")

        } catch (e: Exception) {
            Log.e(TAG, "Google sign-in failed: Unexpected error", e)
            AuthResult.Error("Something went wrong. Please try again later")
        }
    }

    override suspend fun signOut(context: Context): AuthResult<Unit> {
        return try {
            Log.d(TAG, "Signing out user...")

            // Clear Firebase Auth session (works for both email and Google users)
            firebaseAuth.signOut()
            Log.d(TAG, "Firebase session cleared")

            // Clear Credential Manager state to prevent auto-sign-in
            // This is critical for Google users (prevents auto-sign-in on next launch)
            // For email users, this is a safe no-op (nothing to clear)
            try {
                val credentialManager = CredentialManager.create(context)
                credentialManager.clearCredentialState(
                    ClearCredentialStateRequest()
                )
                Log.d(TAG, "Credential Manager state cleared")
            } catch (e: Exception) {
                // Non-critical error - sign out still succeeds
                Log.w(TAG, "Failed to clear Credential Manager state (non-critical)", e)
            }

            Log.d(TAG, "User signed out successfully")
            AuthResult.Success(Unit)

        } catch (e: Exception) {
            Log.e(TAG, "Sign out failed: Unexpected error", e)
            AuthResult.Error("Failed to sign out. Please try again")
        }
    }

    override suspend fun deleteAccount(context: Context): AuthResult<Unit> {
        return try {
            Log.d(TAG, "Deleting user account...")

            val user = firebaseAuth.currentUser
            if (user == null) {
                Log.w(TAG, "Delete account failed: User not authenticated")
                return AuthResult.Error("User not authenticated. Please sign in first.")
            }

            // Delete Firebase account
            user.delete().await()
            Log.d(TAG, "Firebase account deleted")

            // Clear Credential Manager state to prevent auto-sign-in with deleted account
            // Critical for Google users - prevents trying to sign in with deleted account
            // Safe no-op for email users
            try {
                val credentialManager = CredentialManager.create(context)
                credentialManager.clearCredentialState(
                    ClearCredentialStateRequest()
                )
                Log.d(TAG, "Credential Manager state cleared")
            } catch (e: Exception) {
                // Non-critical - account already deleted
                Log.w(TAG, "Failed to clear Credential Manager state (non-critical)", e)
            }

            Log.d(TAG, "User account deleted successfully")
            AuthResult.Success(Unit)

        } catch (e: FirebaseAuthRecentLoginRequiredException) {
            Log.e(TAG, "Delete account failed: Re-authentication required", e)
            AuthResult.Error("Please sign in again to delete your account")

        } catch (e: FirebaseNetworkException) {
            Log.e(TAG, "Delete account failed: Network error", e)
            AuthResult.Error("Network error. Please check your internet connection")

        } catch (e: Exception) {
            Log.e(TAG, "Delete account failed: Unexpected error", e)
            AuthResult.Error("Failed to delete account. Please try again later")
        }
    }

    override suspend fun sendPasswordResetEmail(email: String): AuthResult<Unit> {
        return try {
            val sanitizedEmail = email.trim().lowercase()

            if (!isValidEmail(sanitizedEmail)) {
                Log.w(TAG, "Password reset failed: Invalid email format")
                return AuthResult.Error("Please enter a valid email address")
            }

            Log.d(TAG, "Sending password reset email to: $sanitizedEmail")
            firebaseAuth.sendPasswordResetEmail(sanitizedEmail).await()

            Log.d(TAG, "Password reset email sent successfully")
            AuthResult.Success(Unit)

        } catch (e: FirebaseAuthInvalidUserException) {
            Log.w(TAG, "Password reset: Email not found (but returning success for security)", e)
            AuthResult.Success(Unit)

        } catch (e: FirebaseAuthException) {
            Log.e(TAG, "Firebase error sending password reset: ${e.errorCode}", e)

            val errorMessage = when (e.errorCode) {
                "too-many-requests" ->
                    "Too many requests. Please wait a few minutes before trying again."
                else ->
                    "Failed to send password reset email. Please try again"
            }

            AuthResult.Error(errorMessage)

        } catch (e: FirebaseNetworkException) {
            Log.e(TAG, "Network error sending password reset", e)
            AuthResult.Error("Network error. Please check your internet connection")

        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error sending password reset", e)
            AuthResult.Error("Something went wrong. Please try again later")
        }
    }

    private fun isValidEmail(email: String): Boolean {
        return email.isNotBlank() &&
                android.util.Patterns.EMAIL_ADDRESS.matcher(email).matches()
    }

    private fun validatePassword(password: String): String? {
        return when {
            password.isBlank() -> "Password cannot be empty"
            password.length < MIN_PASSWORD_LENGTH ->
                "Password must be at least $MIN_PASSWORD_LENGTH characters long"
            else -> null
        }
    }

    companion object {
        private const val TAG = "AccountService"
        private const val MIN_PASSWORD_LENGTH = 6
        private const val SHA_256_ALGORITHM = "SHA-256"
        private const val HEX_FORMAT = "%02x"
    }
}
package com.dayyan.firstapp.model.service.impl

import android.app.Activity
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
import com.dayyan.firstapp.model.MfaCodeResult
import com.dayyan.firstapp.model.User
import com.dayyan.firstapp.model.service.AccountService
import com.dayyan.firstapp.model.service.module.ApplicationScope
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException
import com.google.firebase.FirebaseException
import com.google.firebase.FirebaseNetworkException
import com.google.firebase.FirebaseTooManyRequestsException
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseAuthException
import com.google.firebase.auth.FirebaseAuthInvalidCredentialsException
import com.google.firebase.auth.FirebaseAuthMultiFactorException
import com.google.firebase.auth.FirebaseAuthRecentLoginRequiredException
import com.google.firebase.auth.FirebaseAuthUserCollisionException
import com.google.firebase.auth.FirebaseAuthWeakPasswordException
import com.google.firebase.auth.GoogleAuthProvider
import com.google.firebase.auth.MultiFactorResolver
import com.google.firebase.auth.PhoneAuthCredential
import com.google.firebase.auth.PhoneAuthOptions
import com.google.firebase.auth.PhoneAuthProvider
import com.google.firebase.auth.PhoneMultiFactorGenerator
import com.google.firebase.auth.PhoneMultiFactorInfo
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.tasks.await
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import kotlin.coroutines.resume

class AccountServiceImpl @Inject constructor(
    private val firebaseAuth: FirebaseAuth,
    private val credentialManager: CredentialManager,
    @ApplicationScope private val applicationScope: CoroutineScope
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
            AuthResult.Error(e.message ?: "Password must be at least $MIN_PASSWORD_LENGTH characters long")

        } catch (e: FirebaseAuthInvalidCredentialsException) {
            Log.w(TAG, "Sign up failed: Invalid credentials", e)
            AuthResult.Error("Invalid credentials. Please try again")

        } catch (e: FirebaseTooManyRequestsException) {
            Log.w(TAG, "Sign up failed: Too many requests", e)
            AuthResult.Error("Too many attempts. Please wait a few minutes before trying again.")

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

        } catch (e: FirebaseAuthException) {
            Log.w(TAG, "Sign in failed: FirebaseAuthException — ${e.errorCode}", e)
            val errorMessage = when (e.errorCode) {
                "user-not-found" ->
                    "No account found with this email"
                "user-disabled" ->
                    "This account has been disabled. Please contact support."
                else ->
                    "Sign in failed. Please try again"
            }
            AuthResult.Error(errorMessage)

        } catch (e: FirebaseTooManyRequestsException) {
            Log.w(TAG, "Sign in failed: Too many requests", e)
            AuthResult.Error("Too many attempts. Please wait a few minutes before trying again.")

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
        val rawNonce = UUID.randomUUID().toString()
        val digest = MessageDigest.getInstance(SHA_256_ALGORITHM).digest(rawNonce.toByteArray())
        return digest.joinToString("") { HEX_FORMAT.format(it) }
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

    override suspend fun signOut(): AuthResult<Unit> {
        return try {
            Log.d(TAG, "Signing out user...")

            // Clear Credential Manager state to prevent auto-sign-in on next launch.
            // Critical for Google users; a safe no-op for email-only users.
            try {
                credentialManager.clearCredentialState(ClearCredentialStateRequest())
                Log.d(TAG, "Credential Manager state cleared")

            } catch (e: Exception) {
                // Non-critical error - sign out still succeeds
                Log.w(TAG, "Failed to clear Credential Manager state (non-critical)", e)
            }

            // Clear Firebase Auth session (works for both email and Google users)
            firebaseAuth.signOut()
            Log.d(TAG, "Firebase session cleared")

            Log.d(TAG, "User signed out successfully")
            AuthResult.Success(Unit)

        } catch (e: Exception) {
            Log.e(TAG, "Sign out failed: Unexpected error", e)
            AuthResult.Error("Failed to sign out. Please try again")
        }
    }

    override suspend fun deleteAccount(): AuthResult<Unit> {
        return try {
            Log.d(TAG, "Deleting user account...")

            val user = firebaseAuth.currentUser
            if (user == null) {
                Log.w(TAG, "Delete account failed: User not authenticated")
                return AuthResult.Error("User not authenticated. Please sign in first.")
            }

            // Clear Credential Manager state so the deleted account is not auto-selected.
            try {
                credentialManager.clearCredentialState(ClearCredentialStateRequest())
                Log.d(TAG, "Credential Manager state cleared")

            } catch (e: Exception) {
                // Non-critical — credential cache clear failed, proceeding with account deletion
                Log.w(TAG, "Failed to clear Credential Manager state (non-critical)", e)
            }

            // Delete Firebase account
            user.delete().await()
            Log.d(TAG, "Firebase account deleted")

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

        } catch (e: FirebaseAuthException) {
            // Intentional security behaviour: returning Success for user-not-found
            // prevents user-enumeration attacks — callers cannot determine whether
            // an email address is registered. Do NOT change this to return an error.
            if (e.errorCode == "user-not-found") {
                Log.w(TAG, "Password reset: email not registered — returning success for security")
                return AuthResult.Success(Unit)
            }

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

    override fun isUserMfaEnabled(): Boolean? {
        val user = firebaseAuth.currentUser
        if (user == null) {
            Log.w(TAG, "Cannot check MFA: User not authenticated")
            return null
        }

        val isMfaEnabled = user.multiFactor.enrolledFactors.isNotEmpty()
        Log.d(TAG, "MFA enabled: $isMfaEnabled")
        return isMfaEnabled
    }

    override suspend fun checkUserEmailVerificationStatus(): AuthResult<Boolean> {
        return try {
            Log.d(TAG, "Checking email verification status...")

            val user = firebaseAuth.currentUser
            if (user == null) {
                Log.w(TAG, "Cannot check verification: User not authenticated")
                return AuthResult.Error("User not authenticated. Please sign in first.")
            }

            Log.d(TAG, "Reloading user...")
            user.reload().await()

            val isVerified = user.isEmailVerified
            Log.d(TAG, "Email verification status: $isVerified")

            AuthResult.Success(isVerified)

        } catch (e: FirebaseNetworkException) {
            Log.e(TAG, "Network error checking email verification", e)
            AuthResult.Error("Network error. Please check your internet connection")

        } catch (e: Exception) {
            Log.e(TAG, "Error checking email verification", e)
            AuthResult.Error("Failed to check verification status. Please try again")
        }
    }

    override suspend fun sendVerificationEmail(): AuthResult<Unit> {
        return try {
            Log.d(TAG, "Attempting to send verification email...")

            val user = firebaseAuth.currentUser
            if (user == null) {
                Log.w(TAG, "Cannot send verification: User not authenticated")
                return AuthResult.Error("User not authenticated. Please sign in first.")
            }

            if (user.isEmailVerified) {
                Log.d(TAG, "Email already verified, skipping send")
                return AuthResult.Error("Email is already verified")
            }

            Log.d(TAG, "Sending verification email to: ${user.email}")
            user.sendEmailVerification().await()

            Log.d(TAG, "Verification email sent successfully!")
            AuthResult.Success(Unit)

        } catch (e: FirebaseAuthException) {
            Log.e(TAG, "Firebase error sending verification: ${e.errorCode}", e)

            val errorMessage = when (e.errorCode) {
                "too-many-requests" ->
                    "Too many requests. Please wait a few minutes before trying again."
                "user-disabled" ->
                    "Your account has been disabled. Please contact support."
                "invalid-email" ->
                    "Invalid email address."
                else ->
                    "Failed to send verification email. Please try again"
            }

            AuthResult.Error(errorMessage)

        } catch (e: FirebaseNetworkException) {
            Log.e(TAG, "Send verification email failed: Network error", e)
            AuthResult.Error("Network error. Please check your internet connection")

        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error sending verification: ${e.message}", e)
            AuthResult.Error("Failed to send verification email. Please try again")
        }
    }

    /**
     * Resends verification email to the currently authenticated user.
     * This is a convenience method that calls [sendVerificationEmail].
     */
    override suspend fun resendVerificationEmail(): AuthResult<Unit> {
        Log.d(TAG, "Resend verification email requested")
        return sendVerificationEmail()
    }

    override suspend fun sendMfaCodeForMfaEnabling(
        phoneNumber: String,
        activity: Activity
    ): AuthResult<MfaCodeResult> {
        return try {
            val user = firebaseAuth.currentUser
            if (user == null) {
                Log.w(TAG, "MFA enabling failed: User not authenticated")
                return AuthResult.Error("User not authenticated. Please sign in first.")
            }

            val sanitizedPhoneNumber = phoneNumber.trim()

            if (!isValidPhoneNumber(sanitizedPhoneNumber)) {
                Log.w(TAG, "MFA enabling failed: Invalid phone number format")
                return AuthResult.Error("Please enter a valid phone number (e.g., +1234567890)")
            }

            val displayName = "Phone"
            val multiFactorSession = user.multiFactor.session.await()

            suspendCancellableCoroutine { continuation ->

                val resumed = AtomicBoolean(false)

                val callbacks = object : PhoneAuthProvider.OnVerificationStateChangedCallbacks() {

                    override fun onVerificationCompleted(credential: PhoneAuthCredential) {

                        if (resumed.get()) {
                            Log.d(TAG, "onVerificationCompleted fired after onCodeSent — ignoring to avoid race")
                            return
                        }

                        Log.d(TAG, "Phone verification auto-completed — enrolling MFA immediately")

                        val jobRef = AtomicReference<Job?>(null)

                        continuation.invokeOnCancellation {
                            jobRef.get()?.cancel()
                            Log.d(TAG, "Auto-enrollment job cancelled due to continuation cancellation")
                        }

                        val job = applicationScope.launch {
                            try {
                                val assertion = PhoneMultiFactorGenerator.getAssertion(credential)
                                user.multiFactor.enroll(assertion, displayName).await()

                                Log.d(TAG, "MFA auto-enrolled successfully")
                                if (resumed.compareAndSet(false, true) && continuation.isActive) {
                                    continuation.resume(AuthResult.Success(MfaCodeResult.AutoCompleted))
                                }
                            } catch (e: FirebaseAuthException) {
                                Log.e(TAG, "Auto-enrollment failed: ${e.errorCode}", e)
                                val errorMessage = when (e.errorCode) {
                                    "session-expired" ->
                                        "Session expired. Please try again"
                                    "second-factor-already-enrolled" ->
                                        "This phone number is already enrolled for MFA"
                                    "unsupported-first-factor" ->
                                        "Your primary authentication method does not support MFA"
                                    else -> {
                                        Log.e(TAG, "Unexpected error code during auto-enrollment: ${e.errorCode}")
                                        "Failed to enable MFA. Please try again"
                                    }
                                }
                                if (resumed.compareAndSet(false, true) && continuation.isActive) {
                                    continuation.resume(AuthResult.Error(errorMessage))
                                }
                            } catch (e: Exception) {
                                Log.e(TAG, "Unexpected error during auto-enrollment", e)
                                if (resumed.compareAndSet(false, true) && continuation.isActive) {
                                    continuation.resume(AuthResult.Error("Failed to enable MFA. Please try again"))
                                }
                            }
                        }

                        jobRef.set(job)

                        if (!continuation.isActive) {
                            job.cancel()
                            Log.d(TAG, "Continuation already inactive after job launch — cancelled immediately")
                        }
                    }

                    override fun onVerificationFailed(e: FirebaseException) {
                        Log.e(TAG, "Phone verification failed", e)
                        val errorMessage = when (e) {
                            is FirebaseAuthInvalidCredentialsException ->
                                "Invalid phone number format"
                            is FirebaseTooManyRequestsException ->
                                "Too many attempts. Please try again later"
                            is FirebaseNetworkException ->
                                "Network error. Please check your internet connection"
                            else ->
                                "Failed to send MFA verification code. Please try again"
                        }
                        if (resumed.compareAndSet(false, true) && continuation.isActive) {
                            continuation.resume(AuthResult.Error(errorMessage))
                        }
                    }

                    override fun onCodeSent(
                        verificationId: String,
                        token: PhoneAuthProvider.ForceResendingToken
                    ) {
                        Log.d(TAG, "MFA enabling verification code sent successfully")
                        if (resumed.compareAndSet(false, true) && continuation.isActive) {
                            continuation.resume(AuthResult.Success(MfaCodeResult.CodeSent(verificationId)))
                        }
                    }
                }

                val options = PhoneAuthOptions.newBuilder(firebaseAuth)
                    .setPhoneNumber(sanitizedPhoneNumber)
                    .setTimeout(PHONE_VERIFICATION_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    .setActivity(activity)
                    .setCallbacks(callbacks)
                    .setMultiFactorSession(multiFactorSession)
                    .build()

                PhoneAuthProvider.verifyPhoneNumber(options)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Send MFA code for MFA enabling failed: Unexpected error", e)
            AuthResult.Error("Something went wrong. Please try again later")
        }
    }

    override suspend fun enableMfa(
        verificationId: String,
        code: String
    ): AuthResult<Unit> {
        return try {
            Log.d(TAG, "Starting MFA enabling...")

            if (verificationId.isBlank()) {
                Log.w(TAG, "MFA enabling failed: Blank verification ID")
                return AuthResult.Error("Invalid verification session. Please try again")
            }

            if (code.isBlank()) {
                Log.w(TAG, "MFA enabling failed: Empty verification code")
                return AuthResult.Error("Verification code cannot be empty")
            }

            if (code.length != 6 || !code.all { it.isDigit() }) {
                Log.w(TAG, "MFA enabling failed: Invalid code format")
                return AuthResult.Error("Verification code must be 6 digits")
            }

            Log.d(TAG, "Creating phone auth credential...")
            val credential = PhoneAuthProvider.getCredential(verificationId, code)
            val displayName = "Phone"

            enableMfaWithCredential(credential, displayName)

        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error creating credential", e)
            AuthResult.Error("Failed to enable MFA. Please try again later")
        }
    }

    private suspend fun enableMfaWithCredential(
        credential: PhoneAuthCredential,
        displayName: String
    ): AuthResult<Unit> {
        return try {
            Log.d(TAG, "Enabling MFA with credential...")

            val user = firebaseAuth.currentUser
            if (user == null) {
                Log.w(TAG, "MFA enabling failed: User not authenticated")
                return AuthResult.Error("User not authenticated. Please sign in first.")
            }

            Log.d(TAG, "Creating multi-factor assertion...")
            val multiFactorAssertion = PhoneMultiFactorGenerator.getAssertion(credential)

            Log.d(TAG, "Enabling MFA factor with Firebase...")
            user.multiFactor.enroll(multiFactorAssertion, displayName).await()

            Log.d(TAG, "MFA enabling successful!")
            AuthResult.Success(Unit)

        } catch (e: FirebaseAuthException) {
            Log.e(TAG, "Firebase error during MFA enabling: ${e.errorCode}", e)

            val errorMessage = when (e.errorCode) {
                "invalid-verification-code" ->
                    "Invalid verification code. Please try again"
                "session-expired" ->
                    "Verification session expired. Please request a new code"
                "second-factor-already-enrolled" -> {
                    // This is NOT an error — it means Firebase auto-verified
                    // the phone in the background (onVerificationCompleted fired
                    // after onCodeSent, was ignored to prevent a race, but Firebase
                    // had already completed enrollment server-side).
                    // The desired end state — MFA enrolled — is achieved.
                    Log.d(TAG, "MFA already enrolled via auto-verification — treating as success")
                    return AuthResult.Success(Unit)
                }
                else -> {
                    Log.e(TAG, "Unexpected error code during MFA enabling: ${e.errorCode}")
                    "Failed to enable MFA. Please try again"
                }
            }

            AuthResult.Error(errorMessage)

        } catch (e: FirebaseNetworkException) {
            Log.e(TAG, "MFA enabling failed: Network error", e)
            AuthResult.Error("Network error. Please check your internet connection")

        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error during MFA enabling", e)
            AuthResult.Error("Failed to enable MFA. Please try again later")
        }
    }

    override suspend fun disableMfa(): AuthResult<Unit> {
        return try {
            Log.d(TAG, "Starting MFA disable...")

            val user = firebaseAuth.currentUser
            if (user == null) {
                Log.w(TAG, "Cannot disable MFA: User not authenticated")
                return AuthResult.Error("User not authenticated. Please sign in first.")
            }

            val enabledMfa = user.multiFactor.enrolledFactors

            if (enabledMfa.isEmpty()) {
                Log.w(TAG, "Cannot disable MFA: MFA is not enabled")
                return AuthResult.Error("MFA is not enabled")
            }

            val mfaFactor = enabledMfa.first()

            Log.d(TAG, "Disabling MFA: ${mfaFactor.displayName}")
            user.multiFactor.unenroll(mfaFactor).await()

            Log.d(TAG, "MFA disabled successfully!")
            AuthResult.Success(Unit)

        } catch (e: FirebaseAuthRecentLoginRequiredException) {
            Log.e(TAG, "MFA disable failed: Re-authentication required", e)
            AuthResult.Error("Please sign in again to disable MFA")

        } catch (e: FirebaseNetworkException) {
            Log.e(TAG, "MFA disabling failed: Network error", e)
            AuthResult.Error("Network error. Please check your internet connection")

        } catch (e: FirebaseAuthException) {
            Log.e(TAG, "Firebase error disabling MFA: ${e.errorCode}", e)

            val errorMessage = when (e.errorCode) {
                "invalid-multi-factor-session" ->
                    "Session expired. Please try again"
                else ->
                    "Failed to disable MFA. Please try again"
            }

            AuthResult.Error(errorMessage)

        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error disabling MFA", e)
            AuthResult.Error("Failed to disable MFA. Please try again later")
        }
    }

    override suspend fun sendMfaCodeForSignIn(
        resolver: MultiFactorResolver,
        activity: Activity
    ): AuthResult<MfaCodeResult> {
        return try {
            Log.d(TAG, "Sending MFA code for sign-in...")

            // Since the app supports SMS MFA only, the first phone hint is always the target.
            val phoneHint = resolver.hints.firstOrNull { hint ->
                hint is PhoneMultiFactorInfo
            } as? PhoneMultiFactorInfo

            if (phoneHint == null) {
                Log.e(TAG, "MFA sign-in failed: No phone factor found")
                return AuthResult.Error("No phone number found for verification")
            }

            Log.d(TAG, "Sending MFA code to registered phone")

            suspendCancellableCoroutine { continuation ->

                val resumed = AtomicBoolean(false)

                val callbacks = object : PhoneAuthProvider.OnVerificationStateChangedCallbacks() {

                    override fun onVerificationCompleted(credential: PhoneAuthCredential) {

                        if (resumed.get()) {
                            Log.d(TAG, "onVerificationCompleted fired after onCodeSent — ignoring to avoid race")
                            return
                        }

                        Log.d(TAG, "MFA sign-in auto-verified — completing sign-in immediately")

                        val jobRef = AtomicReference<Job?>(null)

                        continuation.invokeOnCancellation {
                            jobRef.get()?.cancel()
                            Log.d(TAG, "Auto-sign in job cancelled due to continuation cancellation")
                        }

                        val job = applicationScope.launch {
                            try {
                                val assertion = PhoneMultiFactorGenerator.getAssertion(credential)
                                resolver.resolveSignIn(assertion).await()

                                Log.d(TAG, "MFA sign-in auto-completed successfully")
                                if (resumed.compareAndSet(false, true) && continuation.isActive) {
                                    continuation.resume(AuthResult.Success(MfaCodeResult.AutoCompleted))
                                }
                            } catch (e: FirebaseAuthException) {
                                Log.e(TAG, "MFA auto sign-in failed: ${e.errorCode}", e)
                                val errorMessage = when (e.errorCode) {
                                    "session-expired",
                                    "invalid-multi-factor-session" ->
                                        "Session expired. Please sign in again"
                                    "quota-exceeded" ->
                                        "Too many attempts. Please try again later"
                                    else -> {
                                        Log.e(TAG, "Unexpected error during MFA auto sign-in: ${e.errorCode}")
                                        "Failed to complete sign-in. Please try again"
                                    }
                                }
                                if (resumed.compareAndSet(false, true) && continuation.isActive) {
                                    continuation.resume(AuthResult.Error(errorMessage))
                                }
                            } catch (e: Exception) {
                                Log.e(TAG, "Unexpected error during MFA auto sign-in", e)
                                if (resumed.compareAndSet(false, true) && continuation.isActive) {
                                    continuation.resume(AuthResult.Error("Failed to complete sign-in. Please try again"))
                                }
                            }
                        }

                        jobRef.set(job)

                        if (!continuation.isActive) {
                            job.cancel()
                            Log.d(TAG, "Continuation already inactive after job launch — cancelled immediately")
                        }
                    }

                    override fun onVerificationFailed(e: FirebaseException) {
                        Log.e(TAG, "MFA sign-in verification failed", e)
                        val errorMessage = when (e) {
                            is FirebaseAuthInvalidCredentialsException ->
                                "Invalid phone number"
                            is FirebaseTooManyRequestsException ->
                                "Too many attempts. Please try again later"
                            is FirebaseNetworkException ->
                                "Network error. Please check your internet connection"
                            else ->
                                "Failed to send MFA verification code. Please try again"
                        }
                        if (resumed.compareAndSet(false, true) && continuation.isActive) {
                            continuation.resume(AuthResult.Error(errorMessage))
                        }
                    }

                    override fun onCodeSent(
                        verificationId: String,
                        token: PhoneAuthProvider.ForceResendingToken
                    ) {
                        Log.d(TAG, "MFA sign-in code sent successfully")
                        if (resumed.compareAndSet(false, true) && continuation.isActive) {
                            continuation.resume(AuthResult.Success(MfaCodeResult.CodeSent(verificationId)))
                        }
                    }
                }

                val options = PhoneAuthOptions.newBuilder(firebaseAuth)
                    .setMultiFactorHint(phoneHint)
                    .setTimeout(PHONE_VERIFICATION_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    .setActivity(activity)
                    .setCallbacks(callbacks)
                    .setMultiFactorSession(resolver.session)
                    .build()

                PhoneAuthProvider.verifyPhoneNumber(options)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Send MFA code for sign-in failed: Unexpected error", e)
            AuthResult.Error("Something went wrong. Please try again later")
        }
    }

    override suspend fun verifyMfaCodeForSignIn(
        resolver: MultiFactorResolver,
        verificationId: String,
        code: String
    ): AuthResult<Unit> {
        return try {
            Log.d(TAG, "Verifying MFA code for sign-in...")

            if (verificationId.isBlank()) {
                Log.w(TAG, "MFA sign-in failed: Blank verification ID")
                return AuthResult.Error("Invalid verification session. Please try again")
            }

            if (code.isBlank()) {
                Log.w(TAG, "MFA sign-in failed: Empty verification code")
                return AuthResult.Error("Verification code cannot be empty")
            }

            if (code.length != 6 || !code.all { it.isDigit() }) {
                Log.w(TAG, "MFA sign-in failed: Invalid code format")
                return AuthResult.Error("Verification code must be 6 digits")
            }

            Log.d(TAG, "Creating phone auth credential...")
            val credential = PhoneAuthProvider.getCredential(verificationId, code)

            Log.d(TAG, "Creating multi-factor assertion...")
            val multiFactorAssertion = PhoneMultiFactorGenerator.getAssertion(credential)

            Log.d(TAG, "Resolving MFA sign-in...")
            resolver.resolveSignIn(multiFactorAssertion).await()

            Log.d(TAG, "MFA sign-in verified successfully!")
            AuthResult.Success(Unit)

        } catch (e: FirebaseAuthException) {
            Log.e(TAG, "Firebase error during MFA sign-in: ${e.errorCode}", e)

            // Handle errors for manual SMS code entry during sign-in
            val errorMessage = when (e.errorCode) {
                "invalid-verification-code" ->
                    "Invalid verification code. Please try again"
                "session-expired" ->
                    "Session expired. Please sign in again"
                "missing-multi-factor-info" ->
                    "Verification failed. Please sign in again"
                "quota-exceeded" ->
                    "Too many attempts. Please try again later"
                // auto-verification resolved sign-in server-side
                // while user was manually entering the code. Sign-in succeeded.
                "invalid-multi-factor-session" -> {
                    Log.d(TAG, "Sign-in already resolved via auto-verification — treating as success")
                    return AuthResult.Success(Unit)
                }
                else -> {
                    Log.e(TAG, "Unexpected error code during MFA sign-in: ${e.errorCode}")
                    "Failed to verify code. Please try again"
                }
            }

            AuthResult.Error(errorMessage)

        } catch (e: FirebaseNetworkException) {
            Log.e(TAG, "MFA sign-in failed: Network error", e)
            AuthResult.Error("Network error. Please check your internet connection")

        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error during MFA sign-in", e)
            AuthResult.Error("Something went wrong. Please try again later")
        }
    }

    private fun isValidEmail(email: String): Boolean {
        return email.isNotBlank() && EMAIL_REGEX.matches(email)
    }

    private fun validatePassword(password: String): String? {
        return when {
            password.isBlank() -> "Password cannot be empty"
            password.length < MIN_PASSWORD_LENGTH ->
                "Password must be at least $MIN_PASSWORD_LENGTH characters long"
            else -> null
        }
    }

    private fun isValidPhoneNumber(phoneNumber: String): Boolean {
        // Must start with +, followed by 1-3 digit country code, then 4-14 digits
        return phoneNumber.matches(PHONE_E164_REGEX)
    }

    companion object {
        private const val TAG = "AccountService"
        private const val MIN_PASSWORD_LENGTH = 6
        private const val SHA_256_ALGORITHM = "SHA-256"
        private const val HEX_FORMAT = "%02x"
        private const val PHONE_VERIFICATION_TIMEOUT_SECONDS = 60L
        private val EMAIL_REGEX = Regex("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")
        private val PHONE_E164_REGEX = Regex("^\\+[1-9]\\d{6,14}$")
    }
}
package com.dayyan.firstapp.model

/**
 * Represents the outcome of requesting an MFA verification code, for both
 * the enrollment flow ([AccountService.sendMfaCodeForMfaEnabling]) and the
 * sign-in flow ([AccountService.sendMfaCodeForSignIn]).
 *
 * Callers must branch on this type to decide whether to show the OTP screen:
 *
 * ```kotlin
 * when (val result = accountService.sendMfaCodeForMfaEnabling(phone, activity)) {
 *     is AuthResult.Success -> when (result.data) {
 *         is MfaCodeResult.AutoCompleted -> { /* already done — skip OTP screen */ }
 *         is MfaCodeResult.CodeSent      -> { showOtpScreen(result.data.verificationId) }
 *     }
 *     is AuthResult.Error -> showError(result.errorMessage)
 *     else -> Unit
 * }
 * ```
 */
sealed interface MfaCodeResult {

    /**
     * Firebase auto-verified the phone number via SMS Retriever, a test phone number,
     * or a cached credential. The MFA operation (enrollment or sign-in) has already
     * completed server-side. **Do not** show an OTP entry screen or call
     * [AccountService.enableMfa] / [AccountService.verifyMfaCodeForSignIn].
     */
    data object AutoCompleted : MfaCodeResult

    /**
     * Firebase sent an SMS code to the user's registered phone number.
     * Show the OTP entry screen and pass [verificationId] — along with the
     * user-entered code — to [AccountService.enableMfa] or
     * [AccountService.verifyMfaCodeForSignIn].
     */
    data class CodeSent(val verificationId: String) : MfaCodeResult
}
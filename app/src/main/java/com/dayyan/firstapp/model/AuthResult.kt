package com.dayyan.firstapp.model

import com.google.firebase.auth.MultiFactorResolver

sealed interface AuthResult<out T> {

    data class Success<T>(val data: T): AuthResult<T>

    data class Error(
        val errorMessage: String
    ): AuthResult<Nothing>

    data class MfaRequired(
        val resolver: MultiFactorResolver
    ): AuthResult<Nothing>
}
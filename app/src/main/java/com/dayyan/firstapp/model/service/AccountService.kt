package com.dayyan.firstapp.model.service

import android.app.Activity
import android.content.Context
import com.dayyan.firstapp.model.AuthResult
import com.dayyan.firstapp.model.User

interface AccountService {

    fun isUserAuthenticated(): Boolean

    fun getCurrentUserId(): String?

    suspend fun signUpWithEmail(email: String, password: String): AuthResult<User>

    suspend fun signInWithEmail(email: String, password: String): AuthResult<Unit>

    suspend fun signInWithGoogle(activity: Activity): AuthResult<User>

    suspend fun signOut(context: Context): AuthResult<Unit>

    suspend fun deleteAccount(context: Context): AuthResult<Unit>

    suspend fun sendPasswordResetEmail(email: String): AuthResult<Unit>

}
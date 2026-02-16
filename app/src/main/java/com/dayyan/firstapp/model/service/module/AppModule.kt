@file:Suppress("unused")

package com.dayyan.firstapp.model.service.module

import com.dayyan.firstapp.model.service.AccountService
import com.dayyan.firstapp.model.service.impl.AccountServiceImpl
import com.google.firebase.auth.FirebaseAuth
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object FirebaseModule {

    @Provides
    @Singleton
    fun provideFirebaseAuth(): FirebaseAuth {
        return FirebaseAuth.getInstance()
    }
}

@Module
@InstallIn(SingletonComponent::class)
abstract class ServiceModule {

    @Binds
    @Singleton
    abstract fun bindAccountService(
        impl: AccountServiceImpl
    ): AccountService
}
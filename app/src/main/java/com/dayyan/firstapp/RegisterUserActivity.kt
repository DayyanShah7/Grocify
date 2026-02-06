package com.dayyan.firstapp

import android.os.Bundle
import android.util.Patterns
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseAuthUserCollisionException
import com.google.firebase.auth.UserProfileChangeRequest

class RegisterUserActivity : AppCompatActivity() {

    private lateinit var auth: FirebaseAuth

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_register_user)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        auth = FirebaseAuth.getInstance()

        val etName = findViewById<EditText>(R.id.etName)
        val etEmail = findViewById<EditText>(R.id.etEmail)
        val etPassword = findViewById<EditText>(R.id.etPassword)
        val etConfirmPassword = findViewById<EditText>(R.id.etConfirmPassword)

        val tvPasswordMismatch = findViewById<TextView>(R.id.tvPasswordMismatch)
        val tvError = findViewById<TextView>(R.id.tvError)

        val btnRegister = findViewById<Button>(R.id.btnRegister)
        val tvBackToLogin = findViewById<TextView>(R.id.tvBackToLogin)

        // Hide errors initially
        tvPasswordMismatch.visibility = View.GONE
        tvError.visibility = View.GONE

        tvBackToLogin.setOnClickListener { finish() }

        btnRegister.setOnClickListener {

            // Reset errors
            tvPasswordMismatch.visibility = View.GONE
            tvError.visibility = View.GONE

            val name = etName.text.toString().trim()
            val email = etEmail.text.toString().trim()
            val password = etPassword.text.toString()
            val confirmPassword = etConfirmPassword.text.toString()

            // Name validation
            if (name.isEmpty()) {
                etName.error = "Name required"
                etName.requestFocus()
                return@setOnClickListener
            }

            // Email validation
            if (email.isEmpty()) {
                etEmail.error = "Email required"
                etEmail.requestFocus()
                return@setOnClickListener
            }
            if (!Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
                etEmail.error = "Enter a valid email"
                etEmail.requestFocus()
                return@setOnClickListener
            }

            // Password validation
            if (password.isEmpty()) {
                etPassword.error = "Password required"
                etPassword.requestFocus()
                return@setOnClickListener
            }
            if (password.length < 6) {
                etPassword.error = "Password must be at least 6 characters"
                etPassword.requestFocus()
                return@setOnClickListener
            }

            if (confirmPassword.isEmpty()) {
                etConfirmPassword.error = "Please retype password"
                etConfirmPassword.requestFocus()
                return@setOnClickListener
            }

            // Password match check
            if (password != confirmPassword) {
                tvPasswordMismatch.text = "Passwords do not match"
                tvPasswordMismatch.visibility = View.VISIBLE
                etConfirmPassword.requestFocus()
                return@setOnClickListener
            }

            btnRegister.isEnabled = false

            auth.createUserWithEmailAndPassword(email, password)
                .addOnSuccessListener { result ->
                    val user = result.user

                    // Store name in Firebase Auth profile
                    val profileUpdates = UserProfileChangeRequest.Builder()
                        .setDisplayName(name)
                        .build()

                    user?.updateProfile(profileUpdates)

                    btnRegister.isEnabled = true
                    Toast.makeText(this, "Registration successful!", Toast.LENGTH_LONG).show()
                    finish()
                }
                .addOnFailureListener { e ->
                    btnRegister.isEnabled = true

                    if (e is FirebaseAuthUserCollisionException) {
                        tvError.text = "User Already Registered"
                        tvError.visibility = View.VISIBLE
                        etEmail.requestFocus()
                        return@addOnFailureListener
                    }

                    tvError.text = e.message ?: "Registration failed"
                    tvError.visibility = View.VISIBLE
                }
        }
    }
}

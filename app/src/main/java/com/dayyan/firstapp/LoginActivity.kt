package com.dayyan.firstapp

import android.content.Intent
import android.os.Bundle
import android.util.Patterns
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.google.firebase.auth.FirebaseAuth

class LoginActivity : AppCompatActivity() {

    private lateinit var auth: FirebaseAuth

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_login)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        auth = FirebaseAuth.getInstance()

        val etEmail = findViewById<EditText>(R.id.editTextText)
        val etPassword = findViewById<EditText>(R.id.editTextTextPassword)
        val btnLogin = findViewById<Button>(R.id.btnLogin)
        val tvError = findViewById<TextView>(R.id.tvError)

        // Hide error initially
        tvError.visibility = View.GONE

        btnLogin.setOnClickListener {
            tvError.visibility = View.GONE

            val email = etEmail.text.toString().trim()
            val password = etPassword.text.toString()

            // Basic validation
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
            if (password.isEmpty()) {
                etPassword.error = "Password required"
                etPassword.requestFocus()
                return@setOnClickListener
            }

            btnLogin.isEnabled = false

            auth.signInWithEmailAndPassword(email, password)
                .addOnSuccessListener {
                    btnLogin.isEnabled = true
                    // Login success -> go to your next screen
                    startActivity(Intent(this, MainActivity2::class.java))
                    finish()
                }
                .addOnFailureListener {
                    btnLogin.isEnabled = true
                    tvError.text = "Incorrect email or password"
                    tvError.visibility = View.VISIBLE
                }
        }

        // Forgot Password
        findViewById<TextView>(R.id.textView4).setOnClickListener {
            startActivity(Intent(this, ForgotPasswordActivity::class.java))
        }

        // New User? Register
        findViewById<TextView>(R.id.tvRegister).setOnClickListener {
            startActivity(Intent(this, RegisterUserActivity::class.java))
        }
    }
}

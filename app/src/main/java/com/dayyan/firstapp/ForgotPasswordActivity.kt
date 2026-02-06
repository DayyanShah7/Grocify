package com.dayyan.firstapp

import android.os.Bundle
import android.util.Patterns
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.firebase.auth.FirebaseAuth

class ForgotPasswordActivity : AppCompatActivity() {

    private lateinit var auth: FirebaseAuth

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_forgot_password)

        auth = FirebaseAuth.getInstance()

        val emailField = findViewById<EditText>(R.id.etResetEmail)
        val sendBtn = findViewById<Button>(R.id.btnSendReset)
        val backBtn = findViewById<TextView>(R.id.tvBackToLogin)
        val errorTv = findViewById<TextView>(R.id.tvResetError)

        fun showError(msg: String) {
            errorTv.text = msg
            errorTv.visibility = TextView.VISIBLE
        }

        fun hideError() {
            errorTv.visibility = TextView.GONE
        }

        sendBtn.setOnClickListener {
            hideError()

            val email = emailField.text.toString().trim()

            if (email.isEmpty()) {
                emailField.error = "Email required"
                return@setOnClickListener
            }
            if (!Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
                emailField.error = "Enter a valid email"
                return@setOnClickListener
            }

            sendBtn.isEnabled = false

            // ✅ Step 1: Check if email exists in Firebase Auth
            auth.fetchSignInMethodsForEmail(email)
                .addOnCompleteListener { checkTask ->
                    if (!checkTask.isSuccessful) {
                        sendBtn.isEnabled = true
                        showError(checkTask.exception?.message ?: "Something went wrong")
                        return@addOnCompleteListener
                    }

                    val methods = checkTask.result?.signInMethods ?: emptyList()

                    // If no sign-in methods => email NOT registered
                    if (methods.isEmpty()) {
                        sendBtn.isEnabled = true
                        showError("Incorrect Email")
                        return@addOnCompleteListener
                    }

                    // ✅ Step 2: Email exists -> send reset link
                    auth.sendPasswordResetEmail(email)
                        .addOnCompleteListener { task ->
                            sendBtn.isEnabled = true
                            if (task.isSuccessful) {
                                Toast.makeText(
                                    this,
                                    "Reset link sent. Check your email.",
                                    Toast.LENGTH_LONG
                                ).show()
                            } else {
                                showError(task.exception?.message ?: "Failed to send reset link.")
                            }
                        }
                }
        }

        backBtn.setOnClickListener { finish() }
    }
}

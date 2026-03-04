package com.dayyan.firstapp

import android.content.Intent
import android.os.Bundle
import android.speech.RecognizerIntent
import android.widget.Button
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import java.util.Locale

class HomeActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_home)

       
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        
        val voiceButton = findViewById<Button>(R.id.btnVoice)
        voiceButton.setOnClickListener {
            startVoiceInput()
        }
    }

    
    private fun startVoiceInput() {
        val intent = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH)
        intent.putExtra(
            RecognizerIntent.EXTRA_LANGUAGE_MODEL,
            RecognizerIntent.LANGUAGE_MODEL_FREE_FORM
        )
        intent.putExtra(
            RecognizerIntent.EXTRA_LANGUAGE,
            Locale.getDefault()
        )

        try {
            startActivityForResult(intent, 100)
        } catch (e: Exception) {
            Toast.makeText(this, "Speech not supported", Toast.LENGTH_SHORT).show()
        }
    }

    
    override fun onActivityResult(
        requestCode: Int,
        resultCode: Int,
        data: Intent?
    ) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == 100 && resultCode == RESULT_OK) {
            val result = data?.getStringArrayListExtra(
                RecognizerIntent.EXTRA_RESULTS
            )
            val spokenText = result?.get(0) ?: ""
            handleVoiceCommand(spokenText)
        }
    }

   
    private fun handleVoiceCommand(text: String) {

        val lowerText = text.lowercase()

        when {
            lowerText.startsWith("add") -> {
                val item = lowerText.removePrefix("add").trim()
                Toast.makeText(this, "ADD: $item", Toast.LENGTH_SHORT).show()
                // TODO: call addItemToFirebase(item)
            }

            lowerText.startsWith("remove") -> {
                val item = lowerText.removePrefix("remove").trim()
                Toast.makeText(this, "REMOVE: $item", Toast.LENGTH_SHORT).show()
                // TODO: call removeItemFromFirebase(item)
            }

            lowerText.startsWith("show") -> {
                Toast.makeText(this, "SHOW LIST", Toast.LENGTH_SHORT).show()
                // TODO: show list logic
            }

            lowerText.startsWith("clear") -> {
                Toast.makeText(this, "CLEAR LIST", Toast.LENGTH_SHORT).show()
                // TODO: clear list logic
            }

            else -> {
                Toast.makeText(this, "Command not recognized", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
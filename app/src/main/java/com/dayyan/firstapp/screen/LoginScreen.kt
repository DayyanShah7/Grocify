package com.dayyan.firstapp

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dayyan.firstapp.ui.theme.FirstAppTheme

@Composable
fun LoginScreen(
    onLoginClick: (String, String) -> Unit = { _, _ -> },
    onForgotPasswordClick: () -> Unit = {}
) {
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = Color(0xFFFDF5E6) // Light cream background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // Title "LOGIN"
            Text(
                text = "LOGIN",
                fontSize = 80.sp,
                fontFamily = FontFamily.Serif,
                color = Color(0xFF5D5D5B),
                fontWeight = FontWeight.Normal,
                modifier = Modifier.padding(bottom = 60.dp)
            )

            // Email Field
            LoginTextField(
                value = email,
                onValueChange = { email = it },
                placeholder = "your email"
            )

            Spacer(modifier = Modifier.height(20.dp))

            // Password Field
            LoginTextField(
                value = password,
                onValueChange = { password = it },
                placeholder = "password",
                isPassword = true
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Forgot Password Link
            Surface(onClick = onForgotPasswordClick, color = Color.Transparent) {
                Text(
                    text = "Forgot password?",
                    color = Color(0xFF8A8A88),
                    fontSize = 24.sp,
                    textDecoration = TextDecoration.Underline
                )
            }

            Spacer(modifier = Modifier.height(60.dp))

            // LOGIN Button
            Button(
                onClick = { onLoginClick(email, password) },
                modifier = Modifier
                    .width(180.dp)
                    .height(60.dp),
                shape = RoundedCornerShape(30.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFFECECEC), // Light gray button background
                    contentColor = Color(0xFF5D5D5B)
                ),
                elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp)
            ) {
                Text(
                    text = "LOGIN",
                    fontSize = 28.sp,
                    fontFamily = FontFamily.Serif,
                    fontWeight = FontWeight.Normal
                )
            }
        }
    }
}

@Composable
fun LoginTextField(
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
    isPassword: Boolean = false
) {
    TextField(
        value = value,
        onValueChange = onValueChange,
        modifier = Modifier
            .fillMaxWidth(0.85f)
            .height(64.dp),
        placeholder = {
            Text(
                text = placeholder,
                color = Color(0xFFA5A5A3),
                fontSize = 24.sp,
                modifier = Modifier.fillMaxWidth(),
                textAlign = androidx.compose.ui.text.style.TextAlign.Center
            )
        },
        shape = RoundedCornerShape(32.dp),
        colors = TextFieldDefaults.colors(
            focusedContainerColor = Color(0xFFFFF9F0),
            unfocusedContainerColor = Color(0xFFFFF9F0),
            disabledContainerColor = Color(0xFFFFF9F0),
            cursorColor = Color(0xFF5D5D5B),
            focusedIndicatorColor = Color.Transparent,
            unfocusedIndicatorColor = Color.Transparent,
            disabledIndicatorColor = Color.Transparent,
        ),
        singleLine = true,
        visualTransformation = if (isPassword) PasswordVisualTransformation() else VisualTransformation.None,
        textStyle = androidx.compose.ui.text.TextStyle(
            fontSize = 24.sp,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
            color = Color(0xFF5D5D5B)
        )
    )
}

@Preview(showBackground = true)
@Composable
fun LoginScreenPreview() {
    FirstAppTheme {
        LoginScreen()
    }
}

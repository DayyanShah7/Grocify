package com.dayyan.firstapp

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
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
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dayyan.firstapp.ui.theme.FirstAppTheme

@Composable
fun RegisterScreen(
    onRegisterClick: (String, String, String) -> Unit = { _, _, _ -> }
) {
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }

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
            // Title "SIGN UP"
            Text(
                text = "SIGN UP",
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

            Spacer(modifier = Modifier.height(20.dp))

            // Confirm Password Field
            LoginTextField(
                value = confirmPassword,
                onValueChange = { confirmPassword = it },
                placeholder = "confirm password",
                isPassword = true
            )

            Spacer(modifier = Modifier.height(60.dp))

            // SIGN UP Button
            Button(
                onClick = { onRegisterClick(email, password, confirmPassword) },
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
                    text = "Sign up",
                    fontSize = 28.sp,
                    fontFamily = FontFamily.Serif,
                    fontWeight = FontWeight.Normal
                )
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun RegisterScreenPreview() {
    FirstAppTheme {
        RegisterScreen()
    }
}

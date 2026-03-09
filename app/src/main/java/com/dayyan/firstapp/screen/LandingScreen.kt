package com.dayyan.firstapp.screen

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dayyan.firstapp.R
import com.dayyan.firstapp.ui.theme.FirstAppTheme

@Composable
fun LandingScreen(
    onGoogleClick: () -> Unit = {},
    onEmailClick: () -> Unit = {},
    onRegisterClick: () -> Unit = {}
) {
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = Color(0xFFFDF5E6) // Match the cream background from your design
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // Logo Text "Grocify"
            Text(
                text = "Grocify",
                fontSize = 80.sp,
                fontFamily = FontFamily.Serif,
                color = Color(0xFF5D5D5B),
                fontWeight = FontWeight.Normal
            )

            Text(
                text = "MAKE YOUR SHOPPING EASIER",
                fontSize = 12.sp,
                letterSpacing = 2.sp,
                color = Color(0xFF8A8A88),
                fontWeight = FontWeight.Medium
            )

            Spacer(modifier = Modifier.height(80.dp))

            // Continue with Google Button
            LandingButton(
                text = "CONTINUE WITH GOOGLE",
                iconRes = R.drawable.ic_google,
                onClick = onGoogleClick
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Continue with Email Button
            LandingButton(
                text = "CONTINUE WITH EMAIL",
                iconRes = R.drawable.ic_email,
                onClick = onEmailClick
            )

            Spacer(modifier = Modifier.height(60.dp))

            // Registration footer
            Text(
                text = "Do not have an account?",
                color = Color(0xFFA5A5A3),
                fontSize = 20.sp
            )
            
            Spacer(modifier = Modifier.height(4.dp))

            Surface(onClick = onRegisterClick, color = Color.Transparent) {
                Text(
                    text = "Click here?",
                    color = Color(0xFFA5A5A3),
                    fontSize = 20.sp,
                    textDecoration = TextDecoration.Underline
                )
            }
        }
    }
}

@Composable
fun LandingButton(
    text: String,
    iconRes: Int,
    onClick: () -> Unit
) {
    Button(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth(0.85f)
            .height(56.dp),
        shape = RoundedCornerShape(16.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = Color(0xFFFFF9F0), // Very light button background
            contentColor = Color(0xFF5D5D5B)
        ),
        elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                painter = painterResource(id = iconRes),
                contentDescription = null,
                modifier = Modifier.size(24.dp),
                tint = Color.Unspecified
            )
            Spacer(modifier = Modifier.width(16.dp))
            Text(
                text = text,
                fontSize = 16.sp,
                fontWeight = FontWeight.Normal,
                letterSpacing = 1.sp
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun LandingScreenPreview() {
    FirstAppTheme {
        LandingScreen()
    }
}

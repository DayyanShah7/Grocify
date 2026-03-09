package com.dayyan.firstapp.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dayyan.firstapp.ui.theme.FirstAppTheme

@Composable
fun EnableMfaScreen(
    onGetOtpClick: (String) -> Unit = {}
) {
    var phoneNumber by remember { mutableStateOf("") }

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
            // Title "Enable MFA"
            Text(
                text = "Enable MFA",
                fontSize = 48.sp,
                fontFamily = FontFamily.Serif,
                color = Color(0xFF5D5D5B),
                fontWeight = FontWeight.Normal
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Subtitle
            Text(
                text = "PLEASE PROVIDE YOUR PHONE NUMBER\nTO ENABLE MFA",
                fontSize = 14.sp,
                color = Color(0xFF8A8A88),
                textAlign = TextAlign.Center,
                lineHeight = 20.sp,
                letterSpacing = 1.sp
            )

            Spacer(modifier = Modifier.height(48.dp))

            // Phone Number Input Row
            Surface(
                modifier = Modifier
                    .fillMaxWidth(0.85f)
                    .height(64.dp),
                shape = RoundedCornerShape(32.dp),
                color = Color.White
            ) {
                Row(
                    modifier = Modifier.fillMaxSize(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Country Code
                    Text(
                        text = "+60",
                        fontSize = 32.sp,
                        color = Color(0xFFA5A5A3),
                        modifier = Modifier.padding(start = 24.dp)
                    )

                    // Vertical Divider
                    Box(
                        modifier = Modifier
                            .padding(horizontal = 12.dp)
                            .width(1.dp)
                            .height(32.dp)
                            .background(Color(0xFFA5A5A3))
                    )

                    // Phone Number Field
                    TextField(
                        value = phoneNumber,
                        onValueChange = { phoneNumber = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = {
                            Text(
                                text = "1234567",
                                color = Color(0xFFA5A5A3),
                                fontSize = 32.sp
                            )
                        },
                        colors = TextFieldDefaults.colors(
                            focusedContainerColor = Color.Transparent,
                            unfocusedContainerColor = Color.Transparent,
                            disabledContainerColor = Color.Transparent,
                            focusedIndicatorColor = Color.Transparent,
                            unfocusedIndicatorColor = Color.Transparent,
                            disabledIndicatorColor = Color.Transparent,
                            cursorColor = Color(0xFF5D5D5B)
                        ),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
                        singleLine = true,
                        textStyle = androidx.compose.ui.text.TextStyle(
                            fontSize = 32.sp,
                            color = Color(0xFF5D5D5B)
                        )
                    )
                }
            }

            Spacer(modifier = Modifier.height(60.dp))

            // get OTP Button
            Button(
                onClick = { onGetOtpClick(phoneNumber) },
                modifier = Modifier
                    .width(200.dp)
                    .height(56.dp),
                shape = RoundedCornerShape(28.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFFECECEC), // Light gray/tan
                    contentColor = Color(0xFF5D5D5B)
                ),
                elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp)
            ) {
                Text(
                    text = "get OTP",
                    fontSize = 24.sp,
                    fontFamily = FontFamily.Serif,
                    fontWeight = FontWeight.Normal
                )
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun EnableMfaScreenPreview() {
    FirstAppTheme {
        EnableMfaScreen()
    }
}

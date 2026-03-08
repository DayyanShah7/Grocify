package com.dayyan.firstapp.screen

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dayyan.firstapp.R
import com.dayyan.firstapp.ui.theme.FirstAppTheme

data class ShoppingItem(
    val name: String,
    val isChecked: Boolean = false
)

data class ShoppingCategory(
    val name: String,
    val items: List<ShoppingItem>
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShoppingListScreen(
    onBackClick: () -> Unit = {},
    onSettingsClick: () -> Unit = {}
) {
    var showVoiceModal by remember { mutableStateOf(false) }

    // Use remember and mutableStateOf to track the list state
    var categories by remember {
        mutableStateOf(
            listOf(
                ShoppingCategory(
                    "Produce", listOf(
                        ShoppingItem("Bananas", false),
                        ShoppingItem("Tomatoes", false),
                        ShoppingItem("Lettuce", false)
                    )
                ),
                ShoppingCategory(
                    "Dairy", listOf(
                        ShoppingItem("Milk", false),
                        ShoppingItem("Cheese", false)
                    )
                ),
                ShoppingCategory(
                    "Bakery", listOf(
                        ShoppingItem("Bread", false)
                    )
                )
            )
        )
    }

    Box(modifier = Modifier.fillMaxSize()) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = Color(0xFFFDF5E6) // Light cream background
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp)
            ) {
                // Top Bar
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(onClick = onBackClick) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = Color(0xFF5D5D5B),
                            modifier = Modifier.size(32.dp)
                        )
                    }
                    Text(
                        text = "Shopping List",
                        fontSize = 28.sp,
                        fontWeight = FontWeight.Normal,
                        color = Color(0xFF5D5D5B)
                    )
                    IconButton(onClick = onSettingsClick) {
                        Icon(
                            painter = painterResource(id = R.drawable.ic_add), // Placeholder for settings icon
                            contentDescription = "Settings",
                            tint = Color(0xFFA5A5A3),
                            modifier = Modifier.size(32.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Search Bar
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp),
                    shape = RoundedCornerShape(28.dp),
                    color = Color.White.copy(alpha = 0.5f),
                    shadowElevation = 0.dp,
                    onClick = { showVoiceModal = true }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(horizontal = 20.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            painter = painterResource(id = R.drawable.ic_mic),
                            contentDescription = "Search",
                            tint = Color(0xFF5D5D5B),
                            modifier = Modifier.size(24.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(32.dp))

                // List
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    categories.forEach { category ->
                        item {
                            Text(
                                text = category.name,
                                fontSize = 24.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF5D5D5B),
                                modifier = Modifier.padding(top = 16.dp, bottom = 8.dp)
                            )
                        }
                        items(category.items) { item ->
                            ShoppingListItemView(
                                item = item,
                                onToggle = {
                                    // Update categories state when an item is clicked
                                    categories = categories.map { cat ->
                                        if (cat.name == category.name) {
                                            cat.copy(items = cat.items.map {
                                                if (it.name == item.name) it.copy(isChecked = !it.isChecked) else it
                                            })
                                        } else cat
                                    }
                                }
                            )
                        }
                    }
                }
            }
        }

        // Voice Input Modal
        if (showVoiceModal) {
            ModalBottomSheet(
                onDismissRequest = { showVoiceModal = false },
                containerColor = Color(0xFFFFF2E1), // Slightly darker cream/peach
                dragHandle = null
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(40.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = "Say what you want to\nadd to the list\ntomatoes? bananas?",
                        fontSize = 20.sp,
                        color = Color(0xFF5D5D5B),
                        textAlign = TextAlign.Center,
                        lineHeight = 28.sp
                    )

                    Spacer(modifier = Modifier.height(60.dp))

                    // Large Blue Mic Button
                    Surface(
                        modifier = Modifier.size(120.dp),
                        shape = CircleShape,
                        color = Color(0xFF8EACFF) // Soft blue
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                painter = painterResource(id = R.drawable.ic_mic),
                                contentDescription = "Listening",
                                tint = Color.White,
                                modifier = Modifier.size(60.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(40.dp))
                }
            }
        }
    }
}

@Composable
fun ShoppingListItemView(item: ShoppingItem, onToggle: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp)
            .clickable { onToggle() }, // Toggle when the whole row is clicked
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(32.dp)
                .clip(CircleShape)
                .background(Color.Transparent),
            contentAlignment = Alignment.Center
        ) {
            Surface(
                modifier = Modifier.fillMaxSize(),
                shape = CircleShape,
                color = Color.Transparent,
                border = BorderStroke(1.5.dp, Color(0xFFA5A5A3))
            ) {
                if (item.isChecked) {
                    Icon(
                        imageVector = Icons.Default.Check,
                        contentDescription = null,
                        tint = Color(0xFF5D5D5B),
                        modifier = Modifier.padding(4.dp)
                    )
                }
            }
        }
        Spacer(modifier = Modifier.width(16.dp))
        Text(
            text = item.name,
            fontSize = 22.sp,
            color = Color(0xFF5D5D5B)
        )
    }
}

@Preview(showBackground = true)
@Composable
fun ShoppingListScreenPreview() {
    FirstAppTheme {
        ShoppingListScreen()
    }
}

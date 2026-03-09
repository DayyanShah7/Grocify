package com.dayyan.firstapp.screen

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dayyan.firstapp.R
import com.dayyan.firstapp.ui.theme.FirstAppTheme

@Composable
fun MyListScreen(
    modifier: Modifier = Modifier,
    onEditClicked: () -> Unit = {},
    onNewListClicked: () -> Unit = {}
) {
    val items = listOf(
        GroceryListItemData(
            title = "Grocery List",
            subtitle = "buy before friday"
        ),
        GroceryListItemData(
            title = "Home",
            subtitle = null
        )
    )

    Surface(
        modifier = modifier.fillMaxSize(),
        color = Color(0xFFFDF5E6) // Light cream background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 24.dp, vertical = 40.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Spacer(modifier = Modifier.weight(1f))
                Text(
                    text = "MY LIST",
                    fontSize = 24.sp,
                    fontFamily = FontFamily.Serif,
                    fontWeight = FontWeight.Normal,
                    color = Color(0xFF5D5D5B),
                    modifier = Modifier.weight(2f),
                    textAlign = TextAlign.Center
                )
                Text(
                    text = "EDIT",
                    fontSize = 20.sp,
                    fontFamily = FontFamily.Serif,
                    color = Color(0xFF5D5D5B),
                    modifier = Modifier
                        .weight(1f)
                        .padding(end = 8.dp),
                    textAlign = TextAlign.End
                )
            }

            Spacer(modifier = Modifier.height(48.dp))

            // List
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(24.dp),
                modifier = Modifier.weight(1f),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                items(items) { item ->
                    GroceryListItem(data = item)
                }

                item {
                    Spacer(modifier = Modifier.height(16.dp))
                    NewListButton(onClick = onNewListClicked)
                }
            }
        }
    }
}

data class GroceryListItemData(
    val title: String,
    val subtitle: String?
)

@Composable
fun GroceryListItem(
    data: GroceryListItemData,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxWidth(0.95f)
            .height(140.dp),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFFFFF2E1) // Slightly darker cream
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = data.title,
                fontSize = 28.sp,
                fontFamily = FontFamily.Serif,
                color = Color(0xFF5D5D5B)
            )
            data.subtitle?.let {
                Text(
                    text = it,
                    fontSize = 18.sp,
                    fontFamily = FontFamily.Serif,
                    color = Color(0xFF5D5D5B)
                )
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row {
                Icon(
                    painter = painterResource(id = R.drawable.ic_person),
                    contentDescription = null,
                    modifier = Modifier.size(32.dp),
                    tint = Color.Unspecified
                )
                Spacer(modifier = Modifier.width(12.dp))
                Icon(
                    painter = painterResource(id = R.drawable.ic_person_add),
                    contentDescription = null,
                    modifier = Modifier.size(32.dp),
                    tint = Color.Unspecified
                )
            }
        }
    }
}

@Composable
fun NewListButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxWidth(0.7f)
            .height(56.dp),
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFFECECEC) // Light gray button background
        ),
        onClick = onClick,
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxSize(),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(
                shape = CircleShape,
                border = BorderStroke(1.dp, Color(0xFF5D5D5B)),
                color = Color.Transparent,
                modifier = Modifier.size(24.dp)
            ) {
                Icon(
                    painter = painterResource(id = R.drawable.ic_add),
                    contentDescription = null,
                    modifier = Modifier.padding(4.dp),
                    tint = Color(0xFF5D5D5B)
                )
            }
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = "New List",
                fontSize = 20.sp,
                fontFamily = FontFamily.Serif,
                color = Color(0xFF5D5D5B)
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun MyListScreenPreview() {
    FirstAppTheme {
        MyListScreen()
    }
}

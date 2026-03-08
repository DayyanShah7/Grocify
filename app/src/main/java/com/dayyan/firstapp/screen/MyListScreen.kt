package com.dayyan.firstapp

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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dayyan.firstapp.ui.theme.FirstAppTheme

@Composable
fun MyListScreen(
    modifier: Modifier = Modifier,
    onEditClicked: () -> Unit = {},
    onNewListClicked: () -> Unit = {}
) {
    val items = listOf(
        GroceryListItemData(
            title = stringResource(R.string.grocery_list_title),
            subtitle = stringResource(R.string.grocery_list_desc)
        ),
        GroceryListItemData(
            title = stringResource(R.string.home_list_title),
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
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.my_list),
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF5D5D5B),
                    modifier = Modifier.weight(1f),
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
                Text(
                    text = stringResource(R.string.edit),
                    fontSize = 18.sp,
                    color = Color(0xFF5D5D5B),
                    modifier = Modifier.padding(end = 8.dp)
                )
            }

            Spacer(modifier = Modifier.height(32.dp))

            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(24.dp),
                modifier = Modifier.weight(1f)
            ) {
                items(items) { item ->
                    GroceryListItem(data = item)
                }

                item {
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
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFFFFF2E1) // Slightly darker cream
        )
    ) {
        Column(
            modifier = Modifier.padding(24.dp)
        ) {
            Text(
                text = data.title,
                fontSize = 24.sp,
                color = Color(0xFF5D5D5B)
            )
            data.subtitle?.let {
                Text(
                    text = it,
                    fontSize = 16.sp,
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
                Spacer(modifier = Modifier.width(8.dp))
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
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(30.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFFFFF2E1)
        ),
        onClick = onClick
    ) {
        Row(
            modifier = Modifier
                .padding(12.dp)
                .fillMaxWidth(),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(
                shape = CircleShape,
                border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF5D5D5B)),
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
                text = stringResource(R.string.new_list),
                fontSize = 20.sp,
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

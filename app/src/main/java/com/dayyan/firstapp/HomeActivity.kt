package com.dayyan.firstapp

import android.annotation.SuppressLint
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.dayyan.firstapp.adapter.GroceryAdapter
import com.dayyan.firstapp.model.GroceryList

class HomeActivity : AppCompatActivity() {

    @SuppressLint("MissingInflatedId")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_home)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        //RecyclerView
        val recyclerView = findViewById<RecyclerView>(R.id.recyclerView)

        val sampleData = listOf(
            GroceryList("Grocery List", "buy before friday"),
            GroceryList("Home", "weekly items")
        )

        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = GroceryAdapter(sampleData)
    }
}

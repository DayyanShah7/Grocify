package com.dayyan.firstapp.model

/**
 * Role hierarchy:
 * OWNER  → full control over list, members, and content
 * EDITOR → content only, no member management
 * VIEWER → read-only, with the ability to check/uncheck items
 */
enum class Role {
    OWNER,
    EDITOR,
    VIEWER
}
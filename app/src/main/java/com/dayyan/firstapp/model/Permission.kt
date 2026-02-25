package com.dayyan.firstapp.model

/**
 * Defines WHAT each role is allowed to do. Nothing else.
 * No database, no DAO, no repository — purely policy.
 *
 * @see Role for the full role hierarchy and definitions.
 */
object Permission {

    /** Any list member can read the list. */
    fun canRead(role: Role?): Boolean = when (role) {
        Role.OWNER, Role.EDITOR, Role.VIEWER -> true
        null -> false
    }

    /** Only OWNER and EDITOR can add or edit items. */
    fun canEditItems(role: Role?): Boolean = when (role) {
        Role.OWNER, Role.EDITOR -> true
        Role.VIEWER, null -> false
    }

    /** Only OWNER and EDITOR can delete items. */
    fun canDeleteItems(role: Role?): Boolean = when (role) {
        Role.OWNER, Role.EDITOR -> true
        Role.VIEWER, null -> false
    }

    /** Any list member can check/uncheck items. */
    fun canCheckItems(role: Role?): Boolean = when (role) {
        Role.OWNER, Role.EDITOR, Role.VIEWER -> true
        null -> false
    }

    /** Only OWNER can delete the entire list. */
    fun canDeleteList(role: Role?): Boolean = when (role) {
        Role.OWNER -> true
        Role.EDITOR, Role.VIEWER, null -> false
    }

    /** Only OWNER can share the list to new members. */
    fun canShareList(role: Role?): Boolean = when (role) {
        Role.OWNER -> true
        Role.EDITOR, Role.VIEWER, null -> false
    }

    /** Only OWNER can change an existing member's role. */
    fun canUpdateMemberRole(role: Role?): Boolean = when (role) {
        Role.OWNER -> true
        Role.EDITOR, Role.VIEWER, null -> false
    }

    /** Only OWNER can remove a member's access. */
    fun canRevokeAccess(role: Role?): Boolean = when (role) {
        Role.OWNER -> true
        Role.EDITOR, Role.VIEWER, null -> false
    }
}
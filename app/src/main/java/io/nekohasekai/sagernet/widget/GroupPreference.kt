package io.nekohasekai.sagernet.widget

import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.ktx.mapX
import rikka.preference.SimpleMenuPreference

fun SimpleMenuPreference.setGroupBean() {
    val groups = SagerDatabase.groupDao.allGroups()

    entries = groups.mapX { it.displayName() }.toTypedArray()
    entryValues = groups.mapX { "${it.id}" }.toTypedArray()

    setOnPreferenceChangeListener { _, newValue ->
        newValue as String
        var sum: CharSequence? = null
        if (newValue.isNotBlank() && newValue != "0") {
            SagerDatabase.groupDao.getById(newValue.toLong())?.displayName()?.let {
                sum = it
            }
        }
        summary = sum ?: entries[newValue.toInt()]
        true
    }
}

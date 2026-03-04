package fr.husi.database.preference

import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.emptyPreferences
import fr.husi.repository.repo
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import okio.Path.Companion.toPath

internal actual fun createConfigurationDataStore(): DataStore<Preferences> {
    val file = repo.resolveDatabaseFile("configuration.preferences_pb")
    return PreferenceDataStoreFactory.createWithPath(
        corruptionHandler = ReplaceFileCorruptionHandler { emptyPreferences() },
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
        produceFile = { file.absolutePath.toPath() },
    )
}

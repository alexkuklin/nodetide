package eu.kuklin.nodetide.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.settingsDataStore: DataStore<Preferences> by preferencesDataStore(name = "settings")

class SettingsStore(private val context: Context) {

    companion object {
        private val RELAY_URL_KEY = stringPreferencesKey("relay_url")
        private val LAST_RELAY_NAME_KEY = stringPreferencesKey("last_relay_name")
    }

    val relayUrl: Flow<String?> = context.settingsDataStore.data.map { prefs ->
        prefs[RELAY_URL_KEY]
    }

    val lastRelayName: Flow<String?> = context.settingsDataStore.data.map { prefs ->
        prefs[LAST_RELAY_NAME_KEY]
    }

    suspend fun setRelayUrl(url: String?, name: String? = null) {
        context.settingsDataStore.edit { prefs ->
            if (url != null) {
                prefs[RELAY_URL_KEY] = url
            } else {
                prefs.remove(RELAY_URL_KEY)
            }
            if (name != null) {
                prefs[LAST_RELAY_NAME_KEY] = name
            }
        }
    }

    suspend fun getRelayUrl(): String? = relayUrl.first()

    suspend fun clear() {
        context.settingsDataStore.edit { prefs ->
            prefs.clear()
        }
    }
}

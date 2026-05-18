package eu.kuklin.nodetide

import android.app.Application
import eu.kuklin.nodetide.data.IdentityStore
import eu.kuklin.nodetide.data.SettingsStore
import eu.kuklin.nodetide.discovery.RelayDiscoveryService
import eu.kuklin.nodetide.network.ApiClient
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking

class NodetideApp : Application() {
    lateinit var identityStore: IdentityStore
        private set

    lateinit var settingsStore: SettingsStore
        private set

    lateinit var discoveryService: RelayDiscoveryService
        private set

    private var apiClient: ApiClient? = null
    private var lastRelayUrl: String? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        identityStore = IdentityStore(this)
        settingsStore = SettingsStore(this)
        discoveryService = RelayDiscoveryService(this)
    }

    fun getApiClient(): ApiClient? {
        val currentUrl = runBlocking { settingsStore.relayUrl.first() }
        if (currentUrl == null) {
            apiClient = null
            lastRelayUrl = null
            return null
        }
        if (currentUrl != lastRelayUrl) {
            apiClient = ApiClient(currentUrl)
            lastRelayUrl = currentUrl
        }
        return apiClient
    }

    companion object {
        lateinit var instance: NodetideApp
            private set
    }
}

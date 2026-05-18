package eu.kuklin.nodetide.discovery

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.util.Log
import eu.kuklin.nodetide.data.DiscoveredRelay
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * Service for discovering nodetide relays on the local network via mDNS/DNS-SD.
 */
class RelayDiscoveryService(private val context: Context) {

    companion object {
        private const val TAG = "RelayDiscovery"
        private const val SERVICE_TYPE = "_nodetide._tcp."
    }

    private val nsdManager: NsdManager by lazy {
        context.getSystemService(Context.NSD_SERVICE) as NsdManager
    }

    private var discoveryListener: NsdManager.DiscoveryListener? = null
    private val discoveredServices = mutableMapOf<String, NsdServiceInfo>()

    /**
     * Discover relays as a Flow that emits discovered relays.
     */
    fun discoverRelays(): Flow<DiscoveredRelay> = callbackFlow {
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) {
                Log.d(TAG, "Discovery started for $serviceType")
            }

            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                Log.d(TAG, "Service found: ${serviceInfo.serviceName}")
                // Resolve the service to get host and port
                resolveService(serviceInfo) { relay ->
                    relay?.let { trySend(it) }
                }
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                Log.d(TAG, "Service lost: ${serviceInfo.serviceName}")
                discoveredServices.remove(serviceInfo.serviceName)
            }

            override fun onDiscoveryStopped(serviceType: String) {
                Log.d(TAG, "Discovery stopped for $serviceType")
            }

            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.e(TAG, "Discovery start failed: $errorCode")
                close(Exception("Discovery start failed: $errorCode"))
            }

            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.e(TAG, "Discovery stop failed: $errorCode")
            }
        }

        discoveryListener = listener

        try {
            nsdManager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start discovery", e)
            close(e)
        }

        awaitClose {
            stopDiscovery()
        }
    }

    /**
     * Discover relays for a specified duration and return all found.
     */
    suspend fun discoverRelaysForDuration(durationMs: Long): List<DiscoveredRelay> {
        val relays = mutableListOf<DiscoveredRelay>()

        return suspendCancellableCoroutine { continuation ->
            val listener = object : NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(serviceType: String) {
                    Log.d(TAG, "Discovery started")
                }

                override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                    Log.d(TAG, "Service found: ${serviceInfo.serviceName}")
                    resolveService(serviceInfo) { relay ->
                        relay?.let {
                            synchronized(relays) {
                                if (relays.none { r -> r.host == it.host && r.port == it.port }) {
                                    relays.add(it)
                                }
                            }
                        }
                    }
                }

                override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
                override fun onDiscoveryStopped(serviceType: String) {}
                override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                    continuation.resume(emptyList())
                }
                override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
            }

            discoveryListener = listener

            try {
                nsdManager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)

                // Schedule stop after duration
                android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                    stopDiscovery()
                    continuation.resume(relays.toList())
                }, durationMs)

            } catch (e: Exception) {
                Log.e(TAG, "Failed to start discovery", e)
                continuation.resume(emptyList())
            }

            continuation.invokeOnCancellation {
                stopDiscovery()
            }
        }
    }

    private fun resolveService(serviceInfo: NsdServiceInfo, callback: (DiscoveredRelay?) -> Unit) {
        nsdManager.resolveService(serviceInfo, object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                Log.e(TAG, "Resolve failed for ${serviceInfo.serviceName}: $errorCode")
                callback(null)
            }

            override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                Log.d(TAG, "Service resolved: ${serviceInfo.serviceName} at ${serviceInfo.host}:${serviceInfo.port}")
                discoveredServices[serviceInfo.serviceName] = serviceInfo

                val properties = mutableMapOf<String, String>()
                serviceInfo.attributes?.forEach { (key, value) ->
                    properties[key] = value?.toString(Charsets.UTF_8) ?: ""
                }

                callback(
                    DiscoveredRelay(
                        name = serviceInfo.serviceName,
                        host = serviceInfo.host?.hostAddress ?: "",
                        port = serviceInfo.port,
                        properties = properties
                    )
                )
            }
        })
    }

    /**
     * Stop discovery.
     */
    fun stopDiscovery() {
        discoveryListener?.let { listener ->
            try {
                nsdManager.stopServiceDiscovery(listener)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to stop discovery", e)
            }
            discoveryListener = null
        }
    }

    /**
     * Get currently discovered relays.
     */
    fun getDiscoveredRelays(): List<DiscoveredRelay> {
        return discoveredServices.values.mapNotNull { serviceInfo ->
            val host = serviceInfo.host?.hostAddress ?: return@mapNotNull null
            val properties = mutableMapOf<String, String>()
            serviceInfo.attributes?.forEach { (key, value) ->
                properties[key] = value?.toString(Charsets.UTF_8) ?: ""
            }
            DiscoveredRelay(
                name = serviceInfo.serviceName,
                host = host,
                port = serviceInfo.port,
                properties = properties
            )
        }
    }
}

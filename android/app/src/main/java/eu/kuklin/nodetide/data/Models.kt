package eu.kuklin.nodetide.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/**
 * Local identity stored on device.
 */
@Serializable
data class LocalIdentity(
    val identityHash: String,
    val name: String?,
    val signingSecretKey: String,  // Hex-encoded Ed25519 secret key
    val signingPublicKey: String,  // Hex-encoded Ed25519 public key
    val encryptionSecretKey: String?,
    val encryptionPublicKey: String?,
    val distributionPoints: List<String> = emptyList(),
    val createdAt: Long = System.currentTimeMillis() / 1000,
    val isDevice: Boolean = false,  // True if attached as device, false if master
    val masterIdentityHash: String? = null  // If device, the master identity hash
)

/**
 * Sigchain event types.
 */
@Serializable
data class SigchainEvent(
    val type: String,
    val timestamp: Long,
    @SerialName("signed_by") val signedBy: String,
    val signature: String,
    // Genesis fields
    val pubkey: String? = null,
    @SerialName("encryption_pubkey") val encryptionPubkey: String? = null,
    val name: String? = null,
    @SerialName("identity_type") val identityType: String? = null,
    @SerialName("distribution_points") val distributionPoints: List<String>? = null,
    // AddDevice fields
    @SerialName("device_pubkey") val devicePubkey: String? = null,
    val label: String? = null,
    val capabilities: List<String>? = null,
    // Other fields as needed
    val seq: Int? = null,
    val prev: String? = null
)

/**
 * Identity information from server.
 */
@Serializable
data class IdentityInfo(
    @SerialName("identity_hash") val identityHash: String,
    val name: String?,
    val pubkey: String,
    @SerialName("encryption_pubkey") val encryptionPubkey: String?,
    @SerialName("identity_type") val identityType: String,
    @SerialName("distribution_points") val distributionPoints: List<String> = emptyList(),
    @SerialName("created_at") val createdAt: Long,
    @SerialName("event_count") val eventCount: Int = 0
)

/**
 * Device info from sigchain.
 */
@Serializable
data class DeviceInfo(
    val pubkey: String,
    val label: String?,
    val capabilities: List<String>,
    val addedAt: Long
)

/**
 * Public message.
 */
@Serializable
data class Message(
    @SerialName("message_hash") val messageHash: String? = null,
    val sender: String,
    val content: MessageContent,
    @SerialName("created_at") val createdAt: Long,
    val signature: String,
    @SerialName("message_type") val messageType: String = "public"
)

@Serializable
data class MessageContent(
    val type: String = "text/plain",
    val body: String
)

/**
 * Discovered relay on local network.
 */
data class DiscoveredRelay(
    val name: String,
    val host: String,
    val port: Int,
    val properties: Map<String, String> = emptyMap()
) {
    val url: String get() = "http://$host:$port"
}

/**
 * Relay status response.
 */
@Serializable
data class RelayStatus(
    val running: Boolean = false,
    val suspended: Boolean = false,
    @SerialName("poll_interval") val pollInterval: Int = 300,
    @SerialName("identities_count") val identitiesCount: Int = 0
)

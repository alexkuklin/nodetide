package eu.kuklin.nodetide.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import eu.kuklin.nodetide.crypto.EncryptionKeyPair
import eu.kuklin.nodetide.crypto.Hash
import eu.kuklin.nodetide.crypto.SigningKeyPair
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val Context.identityDataStore: DataStore<Preferences> by preferencesDataStore(name = "identity")

class IdentityStore(private val context: Context) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    companion object {
        private val IDENTITY_KEY = stringPreferencesKey("local_identity")
        private val SIGCHAIN_KEY = stringPreferencesKey("sigchain")
    }

    /**
     * Get the current local identity.
     */
    val identity: Flow<LocalIdentity?> = context.identityDataStore.data.map { prefs ->
        prefs[IDENTITY_KEY]?.let { json.decodeFromString<LocalIdentity>(it) }
    }

    /**
     * Alias for identity flow (used by UI screens).
     */
    val currentIdentity: Flow<LocalIdentity?> get() = identity

    /**
     * Get the cached sigchain.
     */
    val sigchain: Flow<List<SigchainEvent>> = context.identityDataStore.data.map { prefs ->
        prefs[SIGCHAIN_KEY]?.let { json.decodeFromString<List<SigchainEvent>>(it) } ?: emptyList()
    }

    /**
     * Create a new identity.
     */
    suspend fun createIdentity(
        name: String?,
        distributionPoints: List<String> = emptyList()
    ): LocalIdentity {
        val signingKeyPair = SigningKeyPair.generate()
        val encryptionKeyPair = EncryptionKeyPair.generate()

        val timestamp = System.currentTimeMillis() / 1000

        // Build genesis event (without signature)
        val genesisData = buildMap {
            put("type", "genesis")
            put("timestamp", timestamp)
            put("pubkey", signingKeyPair.publicKeyHex)
            put("encryption_pubkey", encryptionKeyPair.publicKeyHex)
            put("identity_type", "personal")
            put("signed_by", signingKeyPair.publicKeyHex)
            if (!name.isNullOrBlank()) put("name", name)
            if (distributionPoints.isNotEmpty()) put("distribution_points", distributionPoints)
        }

        // Canonical JSON for signing
        val signableJson = canonicalJson(genesisData)
        val signature = signingKeyPair.signHex(signableJson)

        // Compute identity hash
        val identityHash = Hash.identityHash(signableJson)

        val identity = LocalIdentity(
            identityHash = identityHash,
            name = name,
            signingSecretKey = signingKeyPair.secretKeyHex,
            signingPublicKey = signingKeyPair.publicKeyHex,
            encryptionSecretKey = encryptionKeyPair.secretKey.joinToString("") { "%02x".format(it) },
            encryptionPublicKey = encryptionKeyPair.publicKeyHex,
            distributionPoints = distributionPoints,
            createdAt = timestamp,
            isDevice = false
        )

        // Create genesis event
        val genesisEvent = SigchainEvent(
            type = "genesis",
            timestamp = timestamp,
            signedBy = signingKeyPair.publicKeyHex,
            signature = signature,
            pubkey = signingKeyPair.publicKeyHex,
            encryptionPubkey = encryptionKeyPair.publicKeyHex,
            name = name,
            identityType = "personal",
            distributionPoints = distributionPoints.ifEmpty { null }
        )

        // Save identity and sigchain
        context.identityDataStore.edit { prefs ->
            prefs[IDENTITY_KEY] = json.encodeToString(identity)
            prefs[SIGCHAIN_KEY] = json.encodeToString(listOf(genesisEvent))
        }

        return identity
    }

    /**
     * Attach as a device to an existing identity.
     */
    suspend fun attachAsDevice(
        masterIdentityHash: String,
        masterSigchain: List<SigchainEvent>,
        deviceLabel: String?
    ): LocalIdentity {
        val signingKeyPair = SigningKeyPair.generate()
        val timestamp = System.currentTimeMillis() / 1000

        // Get master identity info from genesis
        val genesis = masterSigchain.firstOrNull { it.type == "genesis" }
            ?: throw IllegalArgumentException("No genesis event in sigchain")

        val identity = LocalIdentity(
            identityHash = masterIdentityHash,
            name = genesis.name,
            signingSecretKey = signingKeyPair.secretKeyHex,
            signingPublicKey = signingKeyPair.publicKeyHex,
            encryptionSecretKey = null,
            encryptionPublicKey = genesis.encryptionPubkey,
            distributionPoints = genesis.distributionPoints ?: emptyList(),
            createdAt = timestamp,
            isDevice = true,
            masterIdentityHash = masterIdentityHash
        )

        // Save identity (sigchain will be updated when AddDevice event is submitted)
        context.identityDataStore.edit { prefs ->
            prefs[IDENTITY_KEY] = json.encodeToString(identity)
            prefs[SIGCHAIN_KEY] = json.encodeToString(masterSigchain)
        }

        return identity
    }

    /**
     * Update the cached sigchain.
     */
    suspend fun updateSigchain(events: List<SigchainEvent>) {
        context.identityDataStore.edit { prefs ->
            prefs[SIGCHAIN_KEY] = json.encodeToString(events)
        }
    }

    /**
     * Clear identity data.
     */
    suspend fun clear() {
        context.identityDataStore.edit { prefs ->
            prefs.remove(IDENTITY_KEY)
            prefs.remove(SIGCHAIN_KEY)
        }
    }

    /**
     * Get identity synchronously (for one-time reads).
     */
    suspend fun getIdentity(): LocalIdentity? = identity.first()

    /**
     * Alias for getIdentity (used by UI screens).
     */
    suspend fun getCurrentIdentity(): LocalIdentity? = getIdentity()

    /**
     * Get sigchain synchronously.
     */
    suspend fun getSigchain(): List<SigchainEvent> = sigchain.first()

    /**
     * Save identity directly.
     */
    suspend fun saveIdentity(identity: LocalIdentity) {
        context.identityDataStore.edit { prefs ->
            prefs[IDENTITY_KEY] = json.encodeToString(identity)
        }
    }

    /**
     * Clear identity (alias for clear).
     */
    suspend fun clearIdentity() = clear()

    /**
     * Build canonical JSON for signing (sorted keys, no whitespace).
     */
    private fun canonicalJson(data: Map<String, Any?>): String {
        return buildString {
            append("{")
            data.entries
                .filter { it.value != null }
                .sortedBy { it.key }
                .forEachIndexed { index, (key, value) ->
                    if (index > 0) append(",")
                    append("\"$key\":")
                    append(valueToJson(value))
                }
            append("}")
        }
    }

    private fun valueToJson(value: Any?): String = when (value) {
        null -> "null"
        is String -> "\"$value\""
        is Number -> value.toString()
        is Boolean -> value.toString()
        is List<*> -> "[" + value.joinToString(",") { valueToJson(it) } + "]"
        is Map<*, *> -> canonicalJson(value.mapKeys { it.key.toString() }.mapValues { it.value })
        else -> "\"$value\""
    }
}

// Extension to fix the encryption key hex encoding
private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

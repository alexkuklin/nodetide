package eu.kuklin.nodetide.network

import eu.kuklin.nodetide.data.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

class ApiClient(private val baseUrl: String) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val jsonMediaType = "application/json".toMediaType()

    /**
     * Get identity info from server.
     */
    suspend fun getIdentity(identityHash: String): Result<IdentityResponse> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder()
                .url("$baseUrl/api/identities/$identityHash")
                .get()
                .build()

            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val body = response.body?.string() ?: throw Exception("Empty response")
                Result.success(json.decodeFromString<IdentityResponse>(body))
            } else {
                Result.failure(Exception("HTTP ${response.code}: ${response.message}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Create identity on server (submit genesis event).
     */
    suspend fun createIdentity(genesisEvent: SigchainEvent): Result<CreateIdentityResponse> = withContext(Dispatchers.IO) {
        try {
            val requestBody = json.encodeToString(mapOf("event" to genesisEvent))
                .toRequestBody(jsonMediaType)

            val request = Request.Builder()
                .url("$baseUrl/api/identities")
                .post(requestBody)
                .build()

            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val body = response.body?.string() ?: throw Exception("Empty response")
                Result.success(json.decodeFromString<CreateIdentityResponse>(body))
            } else {
                val errorBody = response.body?.string()
                Result.failure(Exception("HTTP ${response.code}: $errorBody"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Submit event to sigchain.
     */
    suspend fun submitEvent(identityHash: String, event: SigchainEvent): Result<SubmitEventResponse> = withContext(Dispatchers.IO) {
        try {
            val requestBody = json.encodeToString(mapOf("event" to event))
                .toRequestBody(jsonMediaType)

            val request = Request.Builder()
                .url("$baseUrl/api/identities/$identityHash/events")
                .post(requestBody)
                .build()

            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val body = response.body?.string() ?: throw Exception("Empty response")
                Result.success(json.decodeFromString<SubmitEventResponse>(body))
            } else {
                val errorBody = response.body?.string()
                Result.failure(Exception("HTTP ${response.code}: $errorBody"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Get sigchain for identity.
     */
    suspend fun getSigchain(identityHash: String): Result<List<SigchainEvent>> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder()
                .url("$baseUrl/api/identities/$identityHash/sigchain")
                .get()
                .build()

            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val body = response.body?.string() ?: throw Exception("Empty response")
                val sigchainResponse = json.decodeFromString<SigchainResponse>(body)
                Result.success(sigchainResponse.sigchain)
            } else {
                Result.failure(Exception("HTTP ${response.code}: ${response.message}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Get public messages.
     */
    suspend fun getMessages(sender: String? = null, limit: Int = 50): Result<List<Message>> = withContext(Dispatchers.IO) {
        try {
            val url = buildString {
                append("$baseUrl/api/messages?limit=$limit")
                if (sender != null) append("&sender=$sender")
            }

            val request = Request.Builder()
                .url(url)
                .get()
                .build()

            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val body = response.body?.string() ?: throw Exception("Empty response")
                val messagesResponse = json.decodeFromString<MessagesResponse>(body)
                Result.success(messagesResponse.messages)
            } else {
                Result.failure(Exception("HTTP ${response.code}: ${response.message}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Publish a message.
     */
    suspend fun publishMessage(message: Message): Result<PublishMessageResponse> = withContext(Dispatchers.IO) {
        try {
            val requestBody = json.encodeToString(message).toRequestBody(jsonMediaType)

            val request = Request.Builder()
                .url("$baseUrl/api/messages")
                .post(requestBody)
                .build()

            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val body = response.body?.string() ?: throw Exception("Empty response")
                Result.success(json.decodeFromString<PublishMessageResponse>(body))
            } else {
                val errorBody = response.body?.string()
                Result.failure(Exception("HTTP ${response.code}: $errorBody"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Get relay status.
     */
    suspend fun getRelayStatus(): Result<RelayStatus> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder()
                .url("$baseUrl/api/relay/status")
                .get()
                .build()

            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val body = response.body?.string() ?: throw Exception("Empty response")
                Result.success(json.decodeFromString<RelayStatus>(body))
            } else {
                Result.failure(Exception("HTTP ${response.code}: ${response.message}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Health check.
     */
    suspend fun healthCheck(): Result<Boolean> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder()
                .url("$baseUrl/health")
                .get()
                .build()

            val response = client.newCall(request).execute()
            Result.success(response.isSuccessful)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

// Response types
@kotlinx.serialization.Serializable
data class IdentityResponse(
    @kotlinx.serialization.SerialName("identity_hash") val identityHash: String,
    val name: String?,
    val pubkey: String,
    @kotlinx.serialization.SerialName("encryption_pubkey") val encryptionPubkey: String?,
    @kotlinx.serialization.SerialName("identity_type") val identityType: String,
    @kotlinx.serialization.SerialName("distribution_points") val distributionPoints: List<String> = emptyList(),
    val sigchain: List<SigchainEvent> = emptyList()
)

@kotlinx.serialization.Serializable
data class CreateIdentityResponse(
    @kotlinx.serialization.SerialName("identity_hash") val identityHash: String,
    @kotlinx.serialization.SerialName("event_count") val eventCount: Int
)

@kotlinx.serialization.Serializable
data class SubmitEventResponse(
    @kotlinx.serialization.SerialName("event_count") val eventCount: Int,
    val accepted: Boolean = true
)

@kotlinx.serialization.Serializable
data class SigchainResponse(
    @kotlinx.serialization.SerialName("identity_hash") val identityHash: String,
    val sigchain: List<SigchainEvent>
)

@kotlinx.serialization.Serializable
data class MessagesResponse(
    val messages: List<Message>,
    val total: Int = 0
)

@kotlinx.serialization.Serializable
data class PublishMessageResponse(
    @kotlinx.serialization.SerialName("message_hash") val messageHash: String
)

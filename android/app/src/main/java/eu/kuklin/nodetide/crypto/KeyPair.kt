package eu.kuklin.nodetide.crypto

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.Sign
import com.goterl.lazysodium.utils.Key
import com.goterl.lazysodium.utils.KeyPair as SodiumKeyPair

/**
 * Ed25519 signing key pair compatible with nodetide protocol.
 */
class SigningKeyPair private constructor(
    val publicKey: ByteArray,
    val secretKey: ByteArray
) {
    val publicKeyHex: String
        get() = publicKey.toHex()

    val secretKeyHex: String
        get() = secretKey.toHex()

    /**
     * Sign a message and return the signature.
     */
    fun sign(message: ByteArray): ByteArray {
        val signature = ByteArray(Sign.ED25519_BYTES)
        lazySodium.cryptoSignDetached(signature, message, message.size.toLong(), secretKey)
        return signature
    }

    /**
     * Sign a message and return the hex-encoded signature.
     */
    fun signHex(message: ByteArray): String = sign(message).toHex()

    /**
     * Sign a string message.
     */
    fun sign(message: String): ByteArray = sign(message.toByteArray(Charsets.UTF_8))

    fun signHex(message: String): String = sign(message).toHex()

    companion object {
        private val sodium = SodiumAndroid()
        private val lazySodium = LazySodiumAndroid(sodium)

        /**
         * Generate a new random signing key pair.
         */
        fun generate(): SigningKeyPair {
            val keyPair = lazySodium.cryptoSignKeypair()
            return SigningKeyPair(
                publicKey = keyPair.publicKey.asBytes,
                secretKey = keyPair.secretKey.asBytes
            )
        }

        /**
         * Create from existing secret key.
         */
        fun fromSecretKey(secretKey: ByteArray): SigningKeyPair {
            require(secretKey.size == Sign.ED25519_SECRETKEYBYTES) {
                "Secret key must be ${Sign.ED25519_SECRETKEYBYTES} bytes"
            }
            // Extract public key from secret key (last 32 bytes of 64-byte secret key)
            val publicKey = secretKey.copyOfRange(32, 64)
            return SigningKeyPair(publicKey = publicKey, secretKey = secretKey)
        }

        fun fromSecretKeyHex(secretKeyHex: String): SigningKeyPair =
            fromSecretKey(secretKeyHex.hexToBytes())

        /**
         * Verify a signature.
         */
        fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
            return lazySodium.cryptoSignVerifyDetached(signature, message, message.size, publicKey)
        }

        fun verifyHex(publicKeyHex: String, message: ByteArray, signatureHex: String): Boolean =
            verify(publicKeyHex.hexToBytes(), message, signatureHex.hexToBytes())
    }
}

/**
 * X25519 encryption key pair for key exchange.
 */
class EncryptionKeyPair private constructor(
    val publicKey: ByteArray,
    val secretKey: ByteArray
) {
    val publicKeyHex: String
        get() = publicKey.toHex()

    companion object {
        private val sodium = SodiumAndroid()
        private val lazySodium = LazySodiumAndroid(sodium)

        fun generate(): EncryptionKeyPair {
            val keyPair = lazySodium.cryptoBoxKeypair()
            return EncryptionKeyPair(
                publicKey = keyPair.publicKey.asBytes,
                secretKey = keyPair.secretKey.asBytes
            )
        }
    }
}

// Extension functions for hex encoding/decoding
fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "Hex string must have even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

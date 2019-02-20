package se.simbio.encryption

import org.junit.Assert.*
import org.junit.Test

class EncrpytionKTest {

    companion object {
        private const val DEFAULT_KEY = "default_key"
        private const val DEFAULT_SALT = "default_salt"
        private val DEFAULT_IV = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        private const val textToEncrypt = "Sample Kt Text to encrypt"
    }

    @Test
    fun `Basic test`() {
        val encryption = EncryptionK.getDefault(DEFAULT_KEY, DEFAULT_SALT, DEFAULT_IV)
        val encryptedText = encryption.encrypt(textToEncrypt)
        assertNotNull(encryptedText)

        // Should not be null
        encryption.decrypt(encryptedText!!) { s, e ->
            assertNull(e)
            assertNotNull(s)
            assertEquals(s, textToEncrypt)
        }
    }

    @Test
    fun `Encrypt Callback test`() {
        val encryption = EncryptionK.getDefault(DEFAULT_KEY, DEFAULT_SALT, DEFAULT_IV)
        val encryptedText = encryption.encrypt(textToEncrypt) { s, e ->
            assertNull(e)
            assertNotNull(s)
        }
    }
}
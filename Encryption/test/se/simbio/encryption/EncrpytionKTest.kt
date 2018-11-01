package se.simbio.encryption

import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class EncrpytionKTest {

    companion object {
        private const val DEFAULT_KEY = "default_key"
        private const val DEFAULT_SALT = "default_salt"
        private val DEFAULT_IV = byteArrayOf(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
        private const val textToEncrypt = "Sample Kt Text to encrypt"
    }

    @Test
    fun `Basic callback test`() {
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
}
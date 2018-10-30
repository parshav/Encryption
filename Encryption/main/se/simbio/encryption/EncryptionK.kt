package se.simbio.encryption

import java.io.UnsupportedEncodingException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec

import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

import third.part.android.util.Base64

/**
 * A class to make more easy and simple the encrypt routines, this is the core of EncryptionK library
 */
class EncryptionK
/**
 * The private and unique constructor, you should use the EncryptionK.Builder to build your own
 * instance or get the default proving just the sensible information about encryption
 */
private constructor(
        /**
         * The Builder used to create the EncryptionK instance and that contains the information about
         * encryption specifications, this instance need to be private and careful managed
         */
        private val mBuilder: Builder) {

    /**
     * Encrypt a String
     *
     * @param data the String to be encrypted
     *
     * @return the encrypted String or `null` if you send the data as `null`
     *
     * @throws UnsupportedEncodingException       if the Builder charset name is not supported or if
     * the Builder charset name is not supported
     * @throws NoSuchAlgorithmException           if the Builder digest algorithm is not available
     * or if this has no installed provider that can
     * provide the requested by the Builder secret key
     * type or it is `null`, empty or in an invalid
     * format
     * @throws NoSuchPaddingException             if no installed provider can provide the padding
     * scheme in the Builder digest algorithm
     * @throws InvalidAlgorithmParameterException if the specified parameters are inappropriate for
     * the cipher
     * @throws InvalidKeyException                if the specified key can not be used to initialize
     * the cipher instance
     * @throws InvalidKeySpecException            if the specified key specification cannot be used
     * to generate a secret key
     * @throws BadPaddingException                if the padding of the data does not match the
     * padding scheme
     * @throws IllegalBlockSizeException          if the size of the resulting bytes is not a
     * multiple of the cipher block size
     * @throws NullPointerException               if the Builder digest algorithm is `null` or
     * if the specified Builder secret key type is
     * `null`
     * @throws IllegalStateException              if the cipher instance is not initialized for
     * encryption or decryption
     */
    @Throws(UnsupportedEncodingException::class,
            NoSuchAlgorithmException::class,
            NoSuchPaddingException::class,
            InvalidAlgorithmParameterException::class,
            InvalidKeyException::class,
            InvalidKeySpecException::class,
            BadPaddingException::class,
            IllegalBlockSizeException::class)
    fun encrypt(data: String?): String? {
        if (data == null) return null
        val secretKey = mBuilder.mKey?.let { getSecretKey(hashTheKey(it)) } ?: return null
        val dataBytes = mBuilder.mCharsetName?.let { data.toByteArray(charset(it)) } ?: return null
        val cipher = mBuilder.mAlgorithm?.let { Cipher.getInstance(it) } ?: return null
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, mBuilder.mIvParameterSpec, mBuilder.mSecureRandom)
        return Base64.encodeToString(cipher.doFinal(dataBytes), mBuilder.mBase64Mode)
    }

    /**
     * This is a sugar method that calls encrypt method and catch the exceptions returning
     * `null` when it occurs and logging the error
     *
     * @param data the String to be encrypted
     *
     * @return the encrypted String or `null` if you send the data as `null`
     */
    fun encryptOrNull(data: String): String? {
        try {
            return encrypt(data)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }

    }

    /**
     * This is a sugar method that calls encrypt method in background, it is a good idea to use this
     * one instead the default method because encryption can take several time and with this method
     * the process occurs in a AsyncTask, other advantage is the Callback with separated methods,
     * one for success and other for the exception
     *
     * @param data     the String to be encrypted
     * @param callback the Callback to handle the results
     */
    fun encryptAsync(data: String, callback: Callback?) {
        if (callback == null) return
        Thread(Runnable {
            try {
                val encrypt = encrypt(data)
                if (encrypt == null) {
                    callback.onError(Exception("Encrypt return null, it normally occurs when you send a null data"))
                }
                callback.onSuccess(encrypt)
            } catch (e: Exception) {
                callback.onError(e)
            }
        }).start()
    }

    /**
     * Decrypt a String
     *
     * @param data the String to be decrypted
     *
     * @return the decrypted String or `null` if you send the data as `null`
     *
     * @throws UnsupportedEncodingException       if the Builder charset name is not supported or if
     * the Builder charset name is not supported
     * @throws NoSuchAlgorithmException           if the Builder digest algorithm is not available
     * or if this has no installed provider that can
     * provide the requested by the Builder secret key
     * type or it is `null`, empty or in an invalid
     * format
     * @throws NoSuchPaddingException             if no installed provider can provide the padding
     * scheme in the Builder digest algorithm
     * @throws InvalidAlgorithmParameterException if the specified parameters are inappropriate for
     * the cipher
     * @throws InvalidKeyException                if the specified key can not be used to initialize
     * the cipher instance
     * @throws InvalidKeySpecException            if the specified key specification cannot be used
     * to generate a secret key
     * @throws BadPaddingException                if the padding of the data does not match the
     * padding scheme
     * @throws IllegalBlockSizeException          if the size of the resulting bytes is not a
     * multiple of the cipher block size
     * @throws NullPointerException               if the Builder digest algorithm is `null` or
     * if the specified Builder secret key type is
     * `null`
     * @throws IllegalStateException              if the cipher instance is not initialized for
     * encryption or decryption
     */
    @Throws(UnsupportedEncodingException::class, NoSuchAlgorithmException::class, InvalidKeySpecException::class, NoSuchPaddingException::class, InvalidAlgorithmParameterException::class, InvalidKeyException::class, BadPaddingException::class, IllegalBlockSizeException::class)
    fun decrypt(data: String?): String? {
        if (data == null) return null
        val dataBytes = Base64.decode(data, mBuilder.mBase64Mode)
        val secretKey = mBuilder.mKey?.let { getSecretKey(hashTheKey(it)) } ?: return null
        val cipher = Cipher.getInstance(mBuilder.mAlgorithm)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, mBuilder.mIvParameterSpec, mBuilder.mSecureRandom)
        val dataBytesDecrypted = cipher.doFinal(dataBytes)
        return String(dataBytesDecrypted)
    }

    /**
     * This is a sugar method that calls decrypt method and catch the exceptions returning
     * `null` when it occurs and logging the error
     *
     * @param data the String to be decrypted
     *
     * @return the decrypted String or `null` if you send the data as `null`
     */
    fun decryptOrNull(data: String): String? {
        try {
            return decrypt(data)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }

    }

    /**
     * This is a sugar method that calls decrypt method in background, it is a good idea to use this
     * one instead the default method because decryption can take several time and with this method
     * the process occurs in a AsyncTask, other advantage is the Callback with separated methods,
     * one for success and other for the exception
     *
     * @param data     the String to be decrypted
     * @param callback the Callback to handle the results
     */
    fun decryptAsync(data: String, callback: Callback?) {
        if (callback == null) return
        Thread(Runnable {
            try {
                val decrypt = decrypt(data)
                if (decrypt == null) {
                    callback.onError(Exception("Decrypt return null, it normally occurs when you send a null data"))
                }
                callback.onSuccess(decrypt)
            } catch (e: Exception) {
                callback.onError(e)
            }
        }).start()
    }

    /**
     * creates a 128bit salted aes key
     *
     * @param key encoded input key
     *
     * @return aes 128 bit salted key
     *
     * @throws NoSuchAlgorithmException     if no installed provider that can provide the requested
     * by the Builder secret key type
     * @throws UnsupportedEncodingException if the Builder charset name is not supported
     * @throws InvalidKeySpecException      if the specified key specification cannot be used to
     * generate a secret key
     * @throws NullPointerException         if the specified Builder secret key type is `null`
     */
    @Throws(NoSuchAlgorithmException::class, UnsupportedEncodingException::class, InvalidKeySpecException::class)
    private fun getSecretKey(key: CharArray): SecretKey {
        val factory = SecretKeyFactory.getInstance(mBuilder.mSecretKeyType)
        val spec = PBEKeySpec(key, mBuilder.mSalt?.toByteArray(charset(mBuilder.mCharsetName!!)), mBuilder.mIterationCount, mBuilder.mKeyLength)
        val tmp = factory.generateSecret(spec)
        return SecretKeySpec(tmp.encoded, mBuilder.mKeyAlgorithm)
    }

    /**
     * takes in a simple string and performs an sha1 hash
     * that is 128 bits long...we then base64 encode it
     * and return the char array
     *
     * @param key simple inputted string
     *
     * @return sha1 base64 encoded representation
     *
     * @throws UnsupportedEncodingException if the Builder charset name is not supported
     * @throws NoSuchAlgorithmException     if the Builder digest algorithm is not available
     * @throws NullPointerException         if the Builder digest algorithm is `null`
     */
    @Throws(UnsupportedEncodingException::class, NoSuchAlgorithmException::class)
    private fun hashTheKey(key: String): CharArray {
        val messageDigest = MessageDigest.getInstance(mBuilder.mDigestAlgorithm)
        messageDigest.update(key.toByteArray(charset(mBuilder.mCharsetName!!)))
        return Base64.encodeToString(messageDigest.digest(), Base64.NO_PADDING).toCharArray()
    }

    /**
     * When you encrypt or decrypt in callback mode you get noticed of result using this interface
     */
    interface Callback {

        /**
         * Called when encrypt or decrypt job ends and the process was a success
         *
         * @param result the encrypted or decrypted String
         */
        fun onSuccess(result: String?)

        /**
         * Called when encrypt or decrypt job ends and has occurred an error in the process
         *
         * @param exception the Exception related to the error
         */
        fun onError(exception: Exception)

    }

    /**
     * This class is used to create an EncryptionK instance, you should provide ALL data or start
     * with the Default Builder provided by the getDefaultBuilder method
     */
    data class Builder(
            var mIv: ByteArray? = null,
            var mKeyLength: Int = 0,
            var mBase64Mode: Int = 0,
            var mIterationCount: Int = 0,
            var mSalt: String? = null,
            var mKey: String? = null,
            var mAlgorithm: String? = null,
            var mKeyAlgorithm: String? = null,
            var mCharsetName: String? = null,
            var mSecretKeyType: String? = null,
            var mDigestAlgorithm: String? = null,
            var mSecureRandomAlgorithm: String? = null,
            var mSecureRandom: SecureRandom? = null,
            var mIvParameterSpec: IvParameterSpec? = null
    ) {



        fun build(): EncryptionK {
            mSecureRandom = SecureRandom.getInstance(mSecureRandomAlgorithm)
            mIvParameterSpec = IvParameterSpec(mIv)
            return EncryptionK(this)
        }

        companion object {

            /**
             * @return an default builder with the follow defaults:
             * the default char set is UTF-8
             * the default base mode is Base64
             * the Secret Key Type is the PBKDF2WithHmacSHA1
             * the default salt is "some_salt" but can be anything
             * the default length of key is 128
             * the default iteration count is 65536
             * the default algorithm is AES in CBC mode and PKCS 5 Padding
             * the default secure random algorithm is SHA1PRNG
             * the default message digest algorithm SHA1
             */
            fun getDefaultBuilder(key: String, salt: String, iv: ByteArray): Builder {
                return Builder().apply {
                            mIv = iv
                            mKey = key
                            mSalt = salt
                            mKeyLength = 128
                            mKeyAlgorithm = "AES"
                            mCharsetName = "UTF8"
                            mIterationCount = 1
                            mDigestAlgorithm = "SHA1"
                            mBase64Mode = Base64.DEFAULT
                            mAlgorithm = "AES/CBC/PKCS5Padding"
                            mSecureRandomAlgorithm = "SHA1PRNG"
                            mSecretKeyType = "PBKDF2WithHmacSHA1"
                        }
            }
        }

    }

    companion object {

        /**
         * @return an default encryption instance or `null` if occur some Exception, you can
         * create yur own EncryptionK instance using the EncryptionK.Builder
         */
        fun getDefault(key: String, salt: String, iv: ByteArray): EncryptionK? {
            return try {
                Builder.getDefaultBuilder(key, salt, iv).build()
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
                null
            }

        }
    }

}
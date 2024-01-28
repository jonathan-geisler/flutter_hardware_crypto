package xyz.metaman.hardware_crypto

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.annotation.ChecksSdkIntAtLeast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class HardwareCrypto(private val activityBinding: ActivityPluginBinding) {
    companion object {
        const val minimumAndroidSDK = Build.VERSION_CODES.R
        const val notImplementedError = "Not implemented before Android SDK $minimumAndroidSDK"
    }

    private val activity: FragmentActivity = activityBinding.activity as? FragmentActivity ?: throw NotImplementedError()

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private val isEmulator: Boolean
        get() = (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")
                || Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.HARDWARE.contains("goldfish")
                || Build.HARDWARE.contains("ranchu")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.PRODUCT.contains("sdk_google")
                || Build.PRODUCT.contains("google_sdk")
                || Build.PRODUCT.contains("sdk")
                || Build.PRODUCT.contains("sdk_x86")
                || Build.PRODUCT.contains("vbox86p")
                || Build.PRODUCT.contains("emulator")
                || Build.PRODUCT.contains("simulator"))

    @ChecksSdkIntAtLeast(api = minimumAndroidSDK)
    fun isSupported(): Boolean {
        if (Build.VERSION.SDK_INT < minimumAndroidSDK) {
            return false
        }

        if (isEmulator) {
            return true
        }

        val packageManager = activityBinding.activity.applicationContext.packageManager
        return packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    }

    private class BiometricPromptCallback(
        private val continuation: CancellableContinuation<BiometricPrompt.CryptoObject>
    ): BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            super.onAuthenticationError(errorCode, errString)
            continuation.resumeWithException(NotImplementedError())
        }

        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(result)
            val cryptoObject = result.cryptoObject
            if (cryptoObject != null) {
                continuation.resume(cryptoObject)
            } else {
                continuation.resumeWithException(NotImplementedError())
            }
        }

        override fun onAuthenticationFailed() {
            super.onAuthenticationFailed()
            continuation.resumeWithException(NotImplementedError())
        }
    }

    fun generateKeyPair(alias: String): Boolean {
        if (!isSupported()) {
            throw NotImplementedError(notImplementedError)
        }

        val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).run {
            // Enforce strong biometric protection and authentication for every operation
            setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)

            // Use Android's StrongBox
            setIsStrongBoxBacked(!isEmulator)

            // Don't invalidate key after changing biometrics, otherwise we lose it
            setInvalidatedByBiometricEnrollment(false)

            // Require user authentication
            setUserAuthenticationRequired(true)

            setDigests(KeyProperties.DIGEST_SHA256)

            build()
        }

        kpg.initialize(parameterSpec)
        kpg.generateKeyPair()

        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val factory = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
        val keyInfo = factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
        if (!keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware && !isEmulator) {
            keyStore.deleteEntry(alias)
            throw NotImplementedError()
        }

        return true
    }

    fun deleteKeyPair(alias: String): Boolean {
        if (!isSupported()) {
            throw NotImplementedError(notImplementedError)
        }

        keyStore.deleteEntry(alias)
        return true
    }

    suspend fun sign(alias: String, data: ByteArray): ByteArray {
        if (!isSupported()) {
            throw NotImplementedError(notImplementedError)
        }

        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(entry.privateKey)
        authenticate(BiometricPrompt.CryptoObject(signature))
        signature.update(data)
        return signature.sign()
    }

    private suspend fun authenticate(
        cryptoObject: BiometricPrompt.CryptoObject
    ): BiometricPrompt.CryptoObject = suspendCancellableCoroutine { continuation ->
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            BiometricPromptCallback(continuation)
        )

        continuation.invokeOnCancellation { biometricPrompt.cancelAuthentication() }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Biometric login for my app")
                .setSubtitle("Log in using your biometric credential")
                .setNegativeButtonText("Use account password")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()

        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}
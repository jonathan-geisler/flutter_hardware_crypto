package xyz.metaman.hardware_crypto

import androidx.lifecycle.coroutineScope
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.embedding.engine.plugins.lifecycle.FlutterLifecycleAdapter
import kotlinx.coroutines.launch

class HardwareCryptoPlugin: FlutterPlugin, ActivityAware, HardwareCryptoApi {
    private var hardwareCrypto: HardwareCrypto? = null
    private var activityBinding: ActivityPluginBinding? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        HardwareCryptoApi.setUp(binding.binaryMessenger, this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        HardwareCryptoApi.setUp(binding.binaryMessenger, null)
        activityBinding = null
        hardwareCrypto = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activityBinding = binding
        hardwareCrypto = HardwareCrypto(binding)
    }

    override fun onDetachedFromActivityForConfigChanges() {}

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activityBinding = binding
        hardwareCrypto = HardwareCrypto(binding)
    }

    override fun onDetachedFromActivity() {}

    override fun isSupported(): Boolean {
        val hardwareCrypto = this.hardwareCrypto ?: throw NotImplementedError()
        return hardwareCrypto.isSupported()
    }

    override fun generateKeyPair(alias: String, callback: (Result<Boolean>) -> Unit) {
        val hardwareCrypto = this.hardwareCrypto ?: throw NotImplementedError()
        val result = hardwareCrypto.generateKeyPair(alias)
        callback(Result.success(result))
    }

    override fun deleteKeyPair(alias: String, callback: (Result<Boolean>) -> Unit) {
        val hardwareCrypto = this.hardwareCrypto ?: throw NotImplementedError()
        val result = hardwareCrypto.deleteKeyPair(alias)
        callback(Result.success(result))
    }

    override fun sign(alias: String, data: ByteArray, callback: (Result<ByteArray>) -> Unit) {
        try {
            val activityBinding = this.activityBinding ?: throw NotImplementedError()
            val hardwareCrypto = this.hardwareCrypto ?: throw NotImplementedError()
            val lifecycle = FlutterLifecycleAdapter.getActivityLifecycle(activityBinding)
            lifecycle.coroutineScope.launch {
                val signed = hardwareCrypto.sign(alias, data)
                callback(Result.success(signed))
            }
        } catch (e: Exception) {
            callback(Result.failure(e))
        }
    }
}
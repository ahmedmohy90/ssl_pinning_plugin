package com.macif.plugin.sslpinningplugin

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import javax.net.ssl.HttpsURLConnection
import java.security.MessageDigest
import java.security.cert.Certificate
import java.util.concurrent.Executors
import java.util.concurrent.Callable
import java.util.concurrent.Future
import androidx.annotation.NonNull

class SslPinningPlugin : FlutterPlugin, MethodCallHandler {

    private lateinit var channel: MethodChannel

    override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "ssl_pinning_plugin")
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
        try {
            when (call.method) {
                "check" -> handleCheckEvent(call, result)
                else -> result.notImplemented()
            }
        } catch (e: Exception) {
            result.error(e.toString(), "", "")
        }
    }

    private fun handleCheckEvent(call: MethodCall, result: Result) {
        val arguments = call.arguments as HashMap<String, Any>
        val serverURL = arguments["url"] as String
        val allowedFingerprints = arguments["fingerprints"] as List<String>
        val httpMethod = arguments["httpMethod"] as String
        val httpHeaderArgs = arguments["headers"] as Map<String, String>
        val timeout = arguments["timeout"] as Int
        val type = arguments["type"] as String

        val executor = Executors.newSingleThreadExecutor()
        val future: Future<Boolean> = executor.submit(Callable {
            checkConnexion(serverURL, allowedFingerprints, httpHeaderArgs, timeout, type, httpMethod)
        })
        val get: Boolean = future.get()
        executor.shutdown()

        if (get) {
            result.success("CONNECTION_SECURE")
        } else {
            result.error("CONNECTION_NOT_SECURE", "Connection is not secure", "Fingerprint doesn't match")
        }
    }

    private fun checkConnexion(
        serverURL: String,
        allowedFingerprints: List<String>,
        httpHeaderArgs: Map<String, String>,
        timeout: Int,
        type: String,
        httpMethod: String
    ): Boolean {
        val sha: String = getFingerprint(serverURL, timeout, httpHeaderArgs, type, httpMethod)
        return allowedFingerprints.map { it.uppercase().replace("\\s".toRegex(), "") }.contains(sha)
    }

    private fun getFingerprint(
        httpsURL: String,
        connectTimeout: Int,
        httpHeaderArgs: Map<String, String>,
        type: String,
        httpMethod: String
    ): String {
        val url = java.net.URL(httpsURL)
        val httpClient = url.openConnection() as HttpsURLConnection

        if (httpMethod.equals("Head", ignoreCase = true)) httpClient.requestMethod = "HEAD"
        httpHeaderArgs.forEach { (key, value) -> httpClient.setRequestProperty(key, value) }

        httpClient.connect()
        val cert: Certificate = httpClient.serverCertificates[0]
        httpClient.disconnect()

        return hashString(type, cert.encoded)
    }

    private fun hashString(type: String, input: ByteArray) =
        MessageDigest.getInstance(type).digest(input).joinToString("") { "%02X".format(it) }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }
}

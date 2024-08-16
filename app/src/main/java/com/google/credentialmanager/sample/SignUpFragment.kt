package com.google.credentialmanager.sample

import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.credentials.*
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.credentialmanager.sample.databinding.FragmentSignUpBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class SignUpFragment : Fragment() {

    private lateinit var credentialManager: CredentialManager
    private var _binding: FragmentSignUpBinding? = null
    private val binding get() = _binding!!
    private lateinit var listener: SignUpFragmentCallback

    override fun onAttach(context: Context) {
        super.onAttach(context)
        try {
            listener = context as SignUpFragmentCallback
        } catch (castException: ClassCastException) {
            Log.e("SignUpFragment", "Activity must implement SignUpFragmentCallback")
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSignUpBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        credentialManager = CredentialManager.create(requireActivity())

        binding.signUp.setOnClickListener { handleSignUpWithPasskeys() }
        binding.signUpWithPassword.setOnClickListener { handleSignUpWithPassword() }
    }

    private fun handleSignUpWithPassword() {
        binding.password.visibility = View.VISIBLE
        val username = binding.username.text.toString()
        val password = binding.password.text.toString()

        if (username.isEmpty()) {
            binding.username.error = "User name required"
            binding.username.requestFocus()
        } else if (password.isEmpty()) {
            binding.password.error = "Password required"
            binding.password.requestFocus()
        } else {
            lifecycleScope.launch {
                updateUIWhileProcessing(true)
                createPassword(username, password)
                simulateServerDelayAndLogIn()
            }
        }
    }

    private fun simulateServerDelayAndLogIn() {
        Handler(Looper.getMainLooper()).postDelayed({
            DataProvider.setSignedInThroughPasskeys(false)
            updateUIWhileProcessing(false)
            listener.showHome()
        }, 2000)
    }

    private fun handleSignUpWithPasskeys() {
        binding.password.visibility = View.GONE
        val username = binding.username.text.toString()

        if (username.isEmpty()) {
            binding.username.error = "User name required"
            binding.username.requestFocus()
        } else {
            lifecycleScope.launch {
                updateUIWhileProcessing(true)
                val response = createPasskey(username)
                updateUIWhileProcessing(false)
                response?.let {
                    registerResponse()
                    DataProvider.setSignedInThroughPasskeys(true)
                    listener.showHome()
                }
            }
        }
    }

    private suspend fun createPassword(username: String, password: String) {
        val request = CreatePasswordRequest(username, password)
        try {
            credentialManager.createCredential(requireActivity(), request) as CreatePasswordResponse
        } catch (e: CreateCredentialException) {
            Log.e("Auth", "createPassword failed: ${e.message}")
        }
    }

    private suspend fun createPasskey(username: String): CreatePublicKeyCredentialResponse? {
        val responseJson = fetchRegistrationJsonFromServer(username)
        if (responseJson.isEmpty()) return null

        // Asegúrate de que la respuesta JSON contiene todos los campos necesarios
        val requestJson = convertJsonResponse(responseJson)

        if (requestJson.isEmpty()) {
            Log.e("Auth", "Request JSON is empty, cannot proceed")
            return null
        }

        Log.d("Auth", "Request JSON: $requestJson")

        return try {
            val request = CreatePublicKeyCredentialRequest(requestJson)
            credentialManager.createCredential(requireActivity(), request) as CreatePublicKeyCredentialResponse
        } catch (e: CreateCredentialException) {
            handlePasskeyFailure(e)
            null
        }
    }

    private suspend fun fetchRegistrationJsonFromServer(username: String): String {
        return withContext(Dispatchers.IO) {
            try {
                val client = createUnsafeOkHttpClient()
                val request = Request.Builder()
                    .url("https://go-passkey-latest.onrender.com/api/passkey/registerStart") // Actualiza la URL según la ruta de tu servidor
                    .post(JSONObject().put("username", username).toString().toRequestBody())
                    .build()

                client.newCall(request).execute().use { response ->
                    val responseBody = response.body?.string().orEmpty()
                    if (!response.isSuccessful) {
                        Log.e("Auth", "Unexpected response code: ${response.code}")
                        Log.e("Auth", "Response body: $responseBody")
                        ""
                    } else {
                        Log.d("Auth", "Server response: $responseBody")
                        responseBody
                    }
                }
            } catch (e: IOException) {
                Log.e("Auth", "Network request failed", e)
                ""
            }
        }
    }

    private fun convertJsonResponse(responseJson: String): String {
        val originalJson = JSONObject(responseJson)
        Log.d("Auth", "Original JSON: $responseJson")

        // La estructura del JSON debe coincidir con la generada por webAuthn
        return try {
            // Extraer el objeto publicKey del JSON
            val publicKey = originalJson.getJSONObject("publicKey")

            // Extraer las opciones necesarias del JSON
            val challenge = publicKey.getString("challenge")
            val rp = publicKey.getJSONObject("rp")
            val pubKeyCredParams = publicKey.getJSONArray("pubKeyCredParams")
            val authenticatorSelection = publicKey.getJSONObject("authenticatorSelection")
            val user = publicKey.getJSONObject("user")
            // Construir el nuevo JSON según la estructura que tu código espera
            JSONObject().apply {
                put("challenge", challenge)
                put("rp", rp)
                put("pubKeyCredParams", pubKeyCredParams)
                put("authenticatorSelection", authenticatorSelection)
                put("user", user)
            }.toString()
        } catch (e: Exception) {
            Log.e("Auth", "Error building JSON request: ${e.message}")
            ""
        }
    }

    private fun getEncodedUserId(): String {
        val random = SecureRandom()
        val bytes = ByteArray(64)
        random.nextBytes(bytes)
        return Base64.encodeToString(
            bytes,
            Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING
        )
    }

    private fun createUnsafeOkHttpClient(): OkHttpClient {
        // Crear un TrustManager que confíe en todos los certificados
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })

        // Configurar el contexto SSL para usar el TrustManager
        val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, trustAllCerts, SecureRandom())
        }

        // Crear un OkHttpClient con el contexto SSL que confía en todos los certificados
        return OkHttpClient.Builder()
//            .sslSocketFactory(sslContext.socketFactory, trustAllCerts[0] as X509TrustManager)
//            .hostnameVerifier { _, _ -> true }  // Aceptar cualquier hostname
            .build()
    }

    private fun handlePasskeyFailure(e: CreateCredentialException) {
        val msg = when (e) {
            is CreatePublicKeyCredentialDomException -> {
                "An error occurred while creating a passkey, please check logs for additional details."
            }
            is CreateCredentialCancellationException -> {
                "The user intentionally canceled the creation of the passkey."
            }
            else -> {
                "An unexpected error occurred."
            }
        }
        Log.e("Auth", "Error creating passkey: ${e.message}")
        binding.password.error = msg
    }

    private fun registerResponse() {
        // Implementa el manejo de la respuesta del servidor aquí
    }

    private fun updateUIWhileProcessing(isProcessing: Boolean) {
        val visibility = if (isProcessing) View.VISIBLE else View.INVISIBLE
        configureProgress(visibility)
        binding.signUp.isEnabled = !isProcessing
        binding.signUpWithPassword.isEnabled = !isProcessing
    }

    private fun configureProgress(visibility: Int) {
        binding.textProgress.visibility = visibility
        binding.circularProgressIndicator.visibility = visibility
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    interface SignUpFragmentCallback {
        fun showHome()
    }
}

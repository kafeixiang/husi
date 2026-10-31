package fr.husi.ui.profile

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.Stable
import fr.husi.fmt.trojan_go.TrojanGoBean
import fr.husi.ktx.applyDefaultValues
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

@Immutable
internal data class TrojanGoUiState(
    override val customConfig: String = "",
    override val customOutbound: String = "",
    val name: String = "",
    val address: String = "127.0.0.1",
    val port: Int = 443,
    val password: String = "",
    val sni: String = "",
    val type: String = "original",
    val host: String = "",
    val path: String = "",
    val encryption: String = "none",
    val ssMethod: String = "aes-128-gcm",
    val ssPassword: String = "",
    val plugin: String = "",
    val mux: Boolean = false,
    val muxConcurrency: Int = 8,
    val allowInsecure: Boolean = false,
    val udp: Boolean = true,
) : ProfileEditorUiState

@Stable
internal class TrojanGoSettingsViewModel : ProfileEditorViewModel<TrojanGoBean>() {
    override fun createBean() = TrojanGoBean().applyDefaultValues()

    private val _uiState = MutableStateFlow(TrojanGoUiState())
    override val uiState = _uiState.asStateFlow()

    override suspend fun TrojanGoBean.writeToUiState() {
        _uiState.update {
            it.copy(
                customConfig = customConfigJson,
                customOutbound = customOutboundJson,
                name = name,
                address = serverAddress,
                port = serverPort,
                password = password,
                sni = sni,
                type = type,
                host = host,
                path = path,
                encryption = if (encryption.startsWith("ss;")) "ss" else encryption,
                ssMethod = ssMethod,
                ssPassword = ssPassword,
                plugin = plugin,
                mux = mux,
                muxConcurrency = muxConcurrency,
                allowInsecure = allowInsecure,
                udp = udp,
            )
        }
    }

    override fun TrojanGoBean.loadFromUiState() {
        val state = _uiState.value
        customConfigJson = state.customConfig
        customOutboundJson = state.customOutbound
        name = state.name
        serverAddress = state.address
        serverPort = state.port
        password = state.password
        sni = state.sni
        type = state.type
        host = state.host
        path = state.path
        encryption = if (state.encryption == "ss") {
            "ss;${state.ssMethod}:${state.ssPassword}"
        } else {
            "none"
        }
        ssMethod = state.ssMethod
        ssPassword = state.ssPassword
        plugin = state.plugin
        mux = state.mux
        muxConcurrency = state.muxConcurrency
        allowInsecure = state.allowInsecure
        udp = state.udp
    }

    override fun setCustomConfig(config: String) {
        _uiState.update { it.copy(customConfig = config) }
    }

    override fun setCustomOutbound(outbound: String) {
        _uiState.update { it.copy(customOutbound = outbound) }
    }

    fun setName(name: String) = _uiState.update { it.copy(name = name) }
    fun setAddress(address: String) = _uiState.update { it.copy(address = address) }
    fun setPort(port: Int) = _uiState.update { it.copy(port = port) }
    fun setPassword(password: String) = _uiState.update { it.copy(password = password) }
    fun setSni(sni: String) = _uiState.update { it.copy(sni = sni) }
    fun setType(type: String) = _uiState.update { it.copy(type = type) }
    fun setHost(host: String) = _uiState.update { it.copy(host = host) }
    fun setPath(path: String) = _uiState.update { it.copy(path = path) }
    fun setEncryption(encryption: String) = _uiState.update { it.copy(encryption = encryption) }
    fun setSSMethod(method: String) = _uiState.update { it.copy(ssMethod = method) }
    fun setSSPassword(password: String) = _uiState.update { it.copy(ssPassword = password) }
    fun setPlugin(plugin: String) = _uiState.update { it.copy(plugin = plugin) }
    fun setMux(mux: Boolean) = _uiState.update { it.copy(mux = mux) }
    fun setMuxConcurrency(concurrency: Int) = _uiState.update { it.copy(muxConcurrency = concurrency) }
    fun setAllowInsecure(allowInsecure: Boolean) = _uiState.update { it.copy(allowInsecure = allowInsecure) }
    fun setUdp(udp: Boolean) = _uiState.update { it.copy(udp = udp) }
}

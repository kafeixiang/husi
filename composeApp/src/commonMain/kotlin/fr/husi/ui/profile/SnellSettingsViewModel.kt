package fr.husi.ui.profile

import fr.husi.fmt.snell.SnellBean
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

internal data class SnellUiState(
    val name: String = "",
    val address: String = "",
    val port: String = "443",
    val psk: String = "",
    val version: Int = 4,
    val udp: Boolean = true,
    val reuse: Boolean = false,
    val obfsType: String = "none",
    val obfsHost: String = "",
    val tls: Boolean = false,
    val sni: String = "",
    val allowInsecure: Boolean = false,
    val udpOverTcp: Boolean = false,
    val muxType: Int = 0,
    val muxStrategy: Int = 0,
    val muxNumber: Int = 8,
    val muxPadding: Boolean = false,
    val serverMux: Boolean = false,
    override val customConfig: String = "",
    override val customOutbound: String = "",
) : ProfileEditorUiState

internal class SnellSettingsViewModel : ProfileEditorViewModel<SnellBean>() {

    private val _uiState = MutableStateFlow(SnellUiState())
    override val uiState: StateFlow<SnellUiState> = _uiState.asStateFlow()

    override fun createBean(): SnellBean = SnellBean()

    override suspend fun SnellBean.writeToUiState() {
        _uiState.update {
            it.copy(
                name = name,
                address = serverAddress,
                port = serverPort.toString(),
                psk = psk,
                version = version,
                udp = udp,
                reuse = reuse,
                obfsType = obfsType,
                obfsHost = obfsHost,
                tls = tls,
                sni = sni,
                allowInsecure = allowInsecure,
                udpOverTcp = udpOverTcp,
                muxType = serverMuxType,
                muxStrategy = serverMuxStrategy,
                muxNumber = serverMuxNumber,
                muxPadding = serverMuxPadding,
                serverMux = serverMux,
                customConfig = customConfigJson,
                customOutbound = customOutboundJson,
            )
        }
    }

    override fun SnellBean.loadFromUiState() {
        val state = _uiState.value
        name = state.name
        serverAddress = state.address
        serverPort = state.port.toIntOrNull() ?: 443
        psk = state.psk
        version = state.version
        udp = state.udp
        reuse = state.reuse
        obfsType = state.obfsType
        obfsHost = state.obfsHost
        tls = state.tls
        sni = state.sni
        allowInsecure = state.allowInsecure
        udpOverTcp = state.udpOverTcp
        serverMuxType = state.muxType
        serverMuxStrategy = state.muxStrategy
        serverMuxNumber = state.muxNumber
        serverMuxPadding = state.muxPadding
        serverMux = state.serverMux
        customConfigJson = state.customConfig
        customOutboundJson = state.customOutbound
    }

    fun setName(name: String) {
        _uiState.update { it.copy(name = name) }
    }

    fun setAddress(address: String) {
        _uiState.update { it.copy(address = address) }
    }

    fun setPort(port: String) {
        _uiState.update { it.copy(port = port) }
    }

    fun setPsk(psk: String) {
        _uiState.update { it.copy(psk = psk) }
    }

    fun setVersion(version: Int) {
        _uiState.update { 
            it.copy(
                version = version,
                // 当版本切换到 V5 时，自动关闭不兼容的选项
                reuse = if (version >= 4) it.reuse else false,
                obfsType = if (version >= 5) "none" else if (version >= 4 && it.obfsType == "tls") "none" else it.obfsType,
                tls = if (version >= 5) false else it.tls,
                udpOverTcp = if (version >= 5) false else it.udpOverTcp,
                serverMux = if (version >= 4) false else it.serverMux
            )
        }
    }

    fun setUdp(udp: Boolean) {
        _uiState.update { it.copy(udp = udp) }
    }

    fun setReuse(reuse: Boolean) {
        _uiState.update { it.copy(reuse = reuse) }
    }

    fun setObfsType(obfsType: String) {
        _uiState.update { it.copy(obfsType = obfsType) }
    }

    fun setObfsHost(obfsHost: String) {
        _uiState.update { it.copy(obfsHost = obfsHost) }
    }

    fun setTls(tls: Boolean) {
        _uiState.update { it.copy(tls = tls) }
    }

    fun setSni(sni: String) {
        _uiState.update { it.copy(sni = sni) }
    }

    fun setAllowInsecure(allowInsecure: Boolean) {
        _uiState.update { it.copy(allowInsecure = allowInsecure) }
    }

    fun setUdpOverTcp(udpOverTcp: Boolean) {
        _uiState.update { it.copy(udpOverTcp = udpOverTcp) }
    }

    fun setServerMux(enabled: Boolean) {
        _uiState.update { it.copy(serverMux = enabled) }
    }

    fun setMuxType(type: Int) {
        _uiState.update { it.copy(muxType = type) }
    }

    fun setMuxStrategy(strategy: Int) {
        _uiState.update { it.copy(muxStrategy = strategy) }
    }

    fun setMuxNumber(number: Int) {
        _uiState.update { it.copy(muxNumber = number) }
    }

    fun setMuxPadding(enable: Boolean) {
        _uiState.update { it.copy(muxPadding = enable) }
    }

    override fun setCustomConfig(config: String) {
        _uiState.update { it.copy(customConfig = config) }
    }

    override fun setCustomOutbound(outbound: String) {
        _uiState.update { it.copy(customOutbound = outbound) }
    }
}

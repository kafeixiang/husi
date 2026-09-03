package fr.husi.ui.profile

import androidx.compose.runtime.Stable
import fr.husi.fmt.mieru.MieruBean
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

internal data class MieruUiState(
    override val customConfig: String = "",
    override val customOutbound: String = "",
    val name: String = "",
    val address: String = "127.0.0.1",
    val port: Int = 1080,
    val ports: String = "",
    val protocol: String = MieruBean.PROTOCOL_TCP,
    val username: String = "",
    val password: String = "",
    val mtu: Int = 1400,
    val muxNumber: Int = 0,
    val trafficPattern: String = "",
    val handshakeMode: Int = 0,
) : ProfileEditorUiState

@Stable
internal class MieruSettingsViewModel : ProfileEditorViewModel<MieruBean>() {
    private val _uiState = MutableStateFlow(MieruUiState())
    override val uiState: StateFlow<MieruUiState> = _uiState.asStateFlow()

    override fun createBean(): MieruBean = MieruBean()

    override suspend fun MieruBean.writeToUiState() {
        _uiState.update {
            it.copy(
                customConfig = customConfigJson,
                customOutbound = customOutboundJson,
                name = name,
                address = serverAddress,
                port = serverPort,
                ports = serverPorts,
                protocol = protocol,
                username = username,
                password = password,
                mtu = mtu,
                muxNumber = serverMuxNumber,
                trafficPattern = trafficPattern,
                handshakeMode = handshakeMode,
            )
        }
    }

    override fun MieruBean.loadFromUiState() {
        val state = _uiState.value
        customConfigJson = state.customConfig
        customOutboundJson = state.customOutbound
        name = state.name
        serverAddress = state.address
        serverPort = state.port
        serverPorts = state.ports
        protocol = state.protocol
        username = state.username
        password = state.password
        mtu = state.mtu
        serverMuxNumber = state.muxNumber
        trafficPattern = state.trafficPattern
        handshakeMode = state.handshakeMode
    }

    override fun setCustomConfig(config: String) {
        _uiState.update { it.copy(customConfig = config) }
    }

    override fun setCustomOutbound(outbound: String) {
        _uiState.update { it.copy(customOutbound = outbound) }
    }

    fun setName(name: String) {
        _uiState.update { it.copy(name = name) }
    }

    fun setAddress(address: String) {
        _uiState.update { it.copy(address = address) }
    }

    fun setPort(port: Int) {
        _uiState.update { it.copy(port = port) }
    }

    fun setPorts(ports: String) {
        _uiState.update { it.copy(ports = ports) }
    }

    fun setProtocol(protocol: String) {
        _uiState.update { it.copy(protocol = protocol) }
    }

    fun setUsername(username: String) {
        _uiState.update { it.copy(username = username) }
    }

    fun setPassword(password: String) {
        _uiState.update { it.copy(password = password) }
    }

    fun setMtu(mtu: Int) {
        _uiState.update { it.copy(mtu = mtu) }
    }

    fun setMuxNumber(muxNumber: Int) {
        _uiState.update { it.copy(muxNumber = muxNumber) }
    }

    fun setTrafficPattern(trafficPattern: String) {
        _uiState.update { it.copy(trafficPattern = trafficPattern) }
    }

    fun setHandshakeMode(mode: Int) {
        _uiState.update { it.copy(handshakeMode = mode) }
    }
}

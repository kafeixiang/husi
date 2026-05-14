package fr.husi.ui.profile

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.Stable
import fr.husi.fmt.ssr.SSRBean
import fr.husi.ktx.applyDefaultValues
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

@Immutable
internal data class SSRUiState(
    override val customConfig: String = "",
    override val customOutbound: String = "",
    val name: String = "",
    val address: String = "127.0.0.1",
    val port: Int = 8388,
    val method: String = "aes-256-cfb",
    val password: String = "",
    val protocol: String = "origin",
    val protocolParam: String = "",
    val obfs: String = "plain",
    val obfsParam: String = "",
    val group: String = "",
    val udpOverTcp: Boolean = false,
) : ProfileEditorUiState

@Stable
internal class SSRSettingsViewModel : ProfileEditorViewModel<SSRBean>() {
    override fun createBean() = SSRBean().applyDefaultValues()

    private val _uiState = MutableStateFlow(SSRUiState())
    override val uiState = _uiState.asStateFlow()

    override suspend fun SSRBean.writeToUiState() {
        _uiState.update {
            it.copy(
                customConfig = customConfigJson,
                customOutbound = customOutboundJson,
                name = name,
                address = serverAddress,
                port = serverPort,
                method = method,
                password = password,
                protocol = protocol,
                protocolParam = protocolParam,
                obfs = obfs,
                obfsParam = obfsParam,
                group = group,
                udpOverTcp = udpOverTcp,
            )
        }
    }

    override fun SSRBean.loadFromUiState() {
        val state = _uiState.value
        customConfigJson = state.customConfig
        customOutboundJson = state.customOutbound
        name = state.name
        serverAddress = state.address
        serverPort = state.port
        method = state.method
        password = state.password
        protocol = state.protocol
        protocolParam = state.protocolParam
        obfs = state.obfs
        obfsParam = state.obfsParam
        group = state.group
        udpOverTcp = state.udpOverTcp
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

    fun setMethod(method: String) {
        _uiState.update { it.copy(method = method) }
    }

    fun setPassword(password: String) {
        _uiState.update { it.copy(password = password) }
    }

    fun setProtocol(protocol: String) {
        _uiState.update { it.copy(protocol = protocol) }
    }

    fun setProtocolParam(param: String) {
        _uiState.update { it.copy(protocolParam = param) }
    }

    fun setObfs(obfs: String) {
        _uiState.update { it.copy(obfs = obfs) }
    }

    fun setObfsParam(param: String) {
        _uiState.update { it.copy(obfsParam = param) }
    }

    fun setGroup(group: String) {
        _uiState.update { it.copy(group = group) }
    }

    fun setUdpOverTcp(enabled: Boolean) {
        _uiState.update { it.copy(udpOverTcp = enabled) }
    }
}

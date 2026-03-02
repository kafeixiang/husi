package fr.husi.ui.profile

import androidx.compose.runtime.Immutable
import fr.husi.fmt.ssr.ShadowsocksRBean
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

@Immutable
internal data class ShadowsocksRUiState(
    override val customConfig: String = "",
    override val customOutbound: String = "",
    val name: String = "",
    val address: String = "",
    val port: Int = 8388,
    val password: String = "",
    val method: String = "aes-256-cfb",
    val protocol: String = "origin",
    val protocolParam: String = "",
    val obfs: String = "plain",
    val obfsParam: String = "",
    val network: String = "tcp",
) : ProfileSettingsUiState

internal class ShadowsocksRSettingsViewModel : ProfileSettingsViewModel<ShadowsocksRBean>() {
    private val _uiState = MutableStateFlow(ShadowsocksRUiState())
    override val uiState = _uiState.asStateFlow()

    override fun createBean() = ShadowsocksRBean()

    override suspend fun ShadowsocksRBean.writeToUiState() {
        _uiState.update {
            it.copy(
                customConfig = customConfigJson,
                customOutbound = customOutboundJson,
                name = name,
                address = serverAddress,
                port = serverPort,
                password = password,
                method = method,
                protocol = protocol,
                protocolParam = protocolParam,
                obfs = obfs,
                obfsParam = obfsParam,
                network = network,
            )
        }
    }

    override fun ShadowsocksRBean.loadFromUiState() {
        val ui = _uiState.value
        customConfigJson = ui.customConfig
        customOutboundJson = ui.customOutbound
        name = ui.name
        serverAddress = ui.address
        serverPort = ui.port
        password = ui.password
        method = ui.method
        protocol = ui.protocol
        protocolParam = ui.protocolParam
        obfs = ui.obfs
        obfsParam = ui.obfsParam
        network = ui.network
    }

    override fun setCustomConfig(config: String) {
        _uiState.update { it.copy(customConfig = config) }
    }

    override fun setCustomOutbound(outbound: String) {
        _uiState.update { it.copy(customOutbound = outbound) }
    }

    fun setName(value: String) {
        _uiState.update { it.copy(name = value) }
    }

    fun setAddress(value: String) {
        _uiState.update { it.copy(address = value) }
    }

    fun setPort(value: Int) {
        _uiState.update { it.copy(port = value) }
    }

    fun setPassword(value: String) {
        _uiState.update { it.copy(password = value) }
    }

    fun setMethod(value: String) {
        _uiState.update { it.copy(method = value) }
    }

    fun setProtocol(value: String) {
        _uiState.update { it.copy(protocol = value) }
    }

    fun setProtocolParam(value: String) {
        _uiState.update { it.copy(protocolParam = value) }
    }

    fun setObfs(value: String) {
        _uiState.update { it.copy(obfs = value) }
    }

    fun setObfsParam(value: String) {
        _uiState.update { it.copy(obfsParam = value) }
    }

    fun setNetwork(value: String) {
        _uiState.update { it.copy(network = value) }
    }
}

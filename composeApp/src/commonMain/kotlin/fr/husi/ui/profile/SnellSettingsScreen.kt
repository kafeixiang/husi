package fr.husi.ui.profile

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.AnnotatedString
import fr.husi.compose.PortTextField
import fr.husi.compose.PreferenceCategory
import fr.husi.compose.material3.Icon
import fr.husi.compose.material3.Text
import fr.husi.ktx.contentOrUnset
import fr.husi.ktx.intListN
import fr.husi.resources.Res
import fr.husi.resources.allow_insecure
import fr.husi.resources.allow_insecure_sum
import fr.husi.resources.border_inner
import fr.husi.resources.code
import fr.husi.resources.custom_config
import fr.husi.resources.directions_boat
import fr.husi.resources.emoji_symbols
import fr.husi.resources.enable
import fr.husi.resources.experimental_settings
import fr.husi.resources.grid_3x3
import fr.husi.resources.http_host
import fr.husi.resources.hysteria2_obfs_type
import fr.husi.resources.info
import fr.husi.resources.lock
import fr.husi.resources.multiple_stop
import fr.husi.resources.mux_number
import fr.husi.resources.mux_preference
import fr.husi.resources.mux_strategy
import fr.husi.resources.mux_sum
import fr.husi.resources.mux_type
import fr.husi.resources.numbers
import fr.husi.resources.obfs
import fr.husi.resources.padding
import fr.husi.resources.profile_config
import fr.husi.resources.profile_name
import fr.husi.resources.protocol_version
import fr.husi.resources.proxy_cat
import fr.husi.resources.router
import fr.husi.resources.server_address
import fr.husi.resources.server_port
import fr.husi.resources.settings
import fr.husi.resources.snell_psk
import fr.husi.resources.sni
import fr.husi.resources.tcp_reuse
import fr.husi.resources.tls
import fr.husi.resources.type_specimen
import fr.husi.resources.udp
import fr.husi.resources.udp_over_tcp
import fr.husi.resources.view_in_ar
import fr.husi.resources.vpn_key
import fr.husi.resources.warning
import fr.husi.ui.NavRoutes
import me.zhanghai.compose.preference.ListPreference
import me.zhanghai.compose.preference.SwitchPreference
import me.zhanghai.compose.preference.TextFieldPreference
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.resources.vectorResource

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SnellSettingsScreen(
    profileId: Long,
    isSubscription: Boolean,
    onResult: (updated: Boolean) -> Unit,
    onOpenConfigEditor: (NavRoutes.ConfigEditor) -> Unit,
) {
    val viewModel: SnellSettingsViewModel = profileEditorViewModel(
        profileId = profileId,
        isSubscription = isSubscription,
    ) {
        SnellSettingsViewModel()
    }

    ProfileSettingsScreenScaffold(
        title = Res.string.profile_config,
        viewModel = viewModel,
        onResult = onResult,
        onOpenConfigEditor = onOpenConfigEditor,
    ) { uiState, _ ->
        snellSettings(uiState as SnellUiState, viewModel)
    }
}

internal fun LazyListScope.snellSettings(
    uiState: SnellUiState,
    viewModel: SnellSettingsViewModel,
) {
    // 基础设置
    item("name") {
        TextFieldPreference(
            value = uiState.name,
            onValueChange = { viewModel.setName(it) },
            title = { Text(stringResource(Res.string.profile_name)) },
            textToValue = { it },
            icon = { Icon(vectorResource(Res.drawable.emoji_symbols), null) },
            summary = { Text(contentOrUnset(uiState.name)) },
            valueToText = { it },
        )
    }
    item("category_basic") {
        PreferenceCategory(text = { Text(stringResource(Res.string.proxy_cat)) })
    }
    item("address") {
        TextFieldPreference(
            value = uiState.address,
            onValueChange = { viewModel.setAddress(it) },
            title = { Text(stringResource(Res.string.server_address)) },
            textToValue = { it },
            icon = { Icon(vectorResource(Res.drawable.router), null) },
            summary = { Text(contentOrUnset(uiState.address)) },
            valueToText = { it },
        )
    }
    item("port") {
        TextFieldPreference(
            value = uiState.port,
            onValueChange = { viewModel.setPort(it) },
            title = { Text(stringResource(Res.string.server_port)) },
            textToValue = { it },
            icon = { Icon(vectorResource(Res.drawable.directions_boat), null) },
            summary = { Text(uiState.port) },
            valueToText = { it },
            textField = { value, onValueChange, onOk ->
                PortTextField(value, onValueChange, onOk)
            },
        )
    }
    item("psk") {
        TextFieldPreference(
            value = uiState.psk,
            onValueChange = { viewModel.setPsk(it) },
            title = { Text(stringResource(Res.string.snell_psk)) },
            textToValue = { it },
            icon = { Icon(vectorResource(Res.drawable.vpn_key), null) },
            summary = { Text(contentOrUnset(uiState.psk)) },
            valueToText = { it },
        )
    }
    item("version") {
        ListPreference(
            value = uiState.version,
            onValueChange = { viewModel.setVersion(it) },
            values = listOf(1, 2, 3, 4, 5),
            title = { Text(stringResource(Res.string.protocol_version)) },
            summary = { Text(uiState.version.toString()) },
            icon = { Icon(vectorResource(Res.drawable.info), null) },
            valueToText = { AnnotatedString(it.toString()) },
        )
    }
    item("udp") {
        SwitchPreference(
            value = uiState.udp,
            onValueChange = { viewModel.setUdp(it) },
            title = { Text(stringResource(Res.string.udp)) },
            icon = { Icon(vectorResource(Res.drawable.grid_3x3), null) },
        )
    }
    item("reuse") {
        AnimatedVisibility(visible = uiState.version >= 4) {
            SwitchPreference(
                value = uiState.reuse,
                onValueChange = { viewModel.setReuse(it) },
                title = { Text(stringResource(Res.string.tcp_reuse)) },
                icon = { Icon(vectorResource(Res.drawable.settings), null) },
            )
        }
    }

    // 混淆设置
    item("category_obfs") {
        AnimatedVisibility(visible = uiState.version < 5) {
            PreferenceCategory(text = { Text(stringResource(Res.string.obfs)) })
        }
    }
    item("obfs_type") {
        AnimatedVisibility(visible = uiState.version < 5) {
            ListPreference(
                value = uiState.obfsType,
                onValueChange = { viewModel.setObfsType(it) },
                values = if (uiState.version >= 4) listOf("none", "http") else listOf("none", "http", "tls"),
                title = { Text(stringResource(Res.string.hysteria2_obfs_type)) },
                summary = { Text(uiState.obfsType) },
                icon = { Icon(vectorResource(Res.drawable.settings), null) },
                valueToText = { AnnotatedString(it) },
            )
        }
    }
    item("obfs_host") {
        AnimatedVisibility(visible = uiState.version < 5 && uiState.obfsType == "http") {
            TextFieldPreference(
                value = uiState.obfsHost,
                onValueChange = { viewModel.setObfsHost(it) },
                title = { Text(stringResource(Res.string.http_host)) },
                textToValue = { it },
                icon = { Icon(vectorResource(Res.drawable.settings), null) },
                summary = { Text(contentOrUnset(uiState.obfsHost)) },
                valueToText = { it },
            )
        }
    }

    // TLS 设置
    item("category_tls") {
        AnimatedVisibility(visible = uiState.version < 5) {
            PreferenceCategory(text = { Text(stringResource(Res.string.tls)) })
        }
    }
    item("tls") {
        AnimatedVisibility(visible = uiState.version < 5) {
            SwitchPreference(
                value = uiState.tls,
                onValueChange = { viewModel.setTls(it) },
                title = { Text(stringResource(Res.string.tls)) },
                icon = { Icon(vectorResource(Res.drawable.lock), null) },
            )
        }
    }
    item("tls_settings") {
        AnimatedVisibility(visible = uiState.version < 5 && uiState.tls) {
            Column {
                TextFieldPreference(
                    value = uiState.sni,
                    onValueChange = { viewModel.setSni(it) },
                    title = { Text(stringResource(Res.string.sni)) },
                    textToValue = { it },
                    icon = { Icon(vectorResource(Res.drawable.settings), null) },
                    summary = { Text(contentOrUnset(uiState.sni)) },
                    valueToText = { it },
                )
                SwitchPreference(
                    value = uiState.allowInsecure,
                    onValueChange = { viewModel.setAllowInsecure(it) },
                    title = { Text(stringResource(Res.string.allow_insecure)) },
                    summary = { Text(stringResource(Res.string.allow_insecure_sum)) },
                    icon = { Icon(vectorResource(Res.drawable.warning), null) },
                )
            }
        }
    }

    // Mux 设置
    item("category_mux") {
        AnimatedVisibility(visible = uiState.version < 4) {
            PreferenceCategory(text = { Text(stringResource(Res.string.mux_preference)) })
        }
    }
    item("server_mux") {
        AnimatedVisibility(visible = uiState.version < 4) {
            SwitchPreference(
                value = uiState.serverMux,
                onValueChange = { viewModel.setServerMux(it) },
                title = { Text(stringResource(Res.string.enable)) },
                summary = { Text(stringResource(Res.string.mux_sum)) },
                icon = { Icon(vectorResource(Res.drawable.multiple_stop), null) },
            )
        }
    }
    item("mux_settings") {
        AnimatedVisibility(visible = uiState.version < 4 && uiState.serverMux) {
            Column {
                ListPreference(
                    value = uiState.muxType,
                    onValueChange = { viewModel.setMuxType(it) },
                    values = intListN(muxTypes.size),
                    title = { Text(stringResource(Res.string.mux_type)) },
                    summary = { Text(muxTypes[uiState.muxType]) },
                    icon = { Icon(vectorResource(Res.drawable.type_specimen), null) },
                    valueToText = { AnnotatedString(muxTypes[it]) },
                )
                ListPreference(
                    value = uiState.muxStrategy,
                    onValueChange = { viewModel.setMuxStrategy(it) },
                    values = intListN(muxStrategies.size),
                    title = { Text(stringResource(Res.string.mux_strategy)) },
                    summary = { Text(stringResource(muxStrategies[uiState.muxStrategy])) },
                    icon = { Icon(vectorResource(Res.drawable.view_in_ar), null) },
                    valueToText = { AnnotatedString(stringResource(muxStrategies[it])) },
                )
                TextFieldPreference(
                    value = uiState.muxNumber,
                    onValueChange = { viewModel.setMuxNumber(it) },
                    title = { Text(stringResource(Res.string.mux_number)) },
                    textToValue = { it.toIntOrNull() ?: 8 },
                    summary = { Text(uiState.muxNumber.toString()) },
                    icon = { Icon(vectorResource(Res.drawable.numbers), null) },
                    valueToText = { it.toString() },
                )
                SwitchPreference(
                    value = uiState.muxPadding,
                    onValueChange = { viewModel.setMuxPadding(it) },
                    title = { Text(stringResource(Res.string.padding)) },
                    icon = { Icon(vectorResource(Res.drawable.border_inner), null) },
                )
            }
        }
    }

    // 实验性与自定义
    item("category_experimental") {
        AnimatedVisibility(visible = uiState.version < 5) {
            PreferenceCategory(text = { Text(stringResource(Res.string.experimental_settings)) })
        }
    }
    item("udp_over_tcp") {
        AnimatedVisibility(visible = uiState.version < 5) {
            SwitchPreference(
                value = uiState.udpOverTcp,
                onValueChange = { viewModel.setUdpOverTcp(it) },
                title = { Text(stringResource(Res.string.udp_over_tcp)) },
                icon = { Icon(vectorResource(Res.drawable.grid_3x3), null) },
            )
        }
    }

    item("category_custom") {
        PreferenceCategory(text = { Text(stringResource(Res.string.custom_config)) })
    }
    item("custom_config") {
        TextFieldPreference(
            value = uiState.customConfig,
            onValueChange = { viewModel.setCustomConfig(it) },
            title = { Text(stringResource(Res.string.custom_config)) },
            textToValue = { it },
            icon = { Icon(vectorResource(Res.drawable.code), null) },
            summary = { Text(contentOrUnset(uiState.customConfig)) },
            valueToText = { it },
        )
    }
}

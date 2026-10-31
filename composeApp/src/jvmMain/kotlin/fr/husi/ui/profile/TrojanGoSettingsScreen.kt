package fr.husi.ui.profile

import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.AnnotatedString
import fr.husi.compose.IconMaskColors
import fr.husi.compose.ListPreference
import fr.husi.compose.MaskedIcon
import fr.husi.compose.PasswordPreference
import fr.husi.compose.PreferenceCategory
import fr.husi.compose.SwitchPreference
import fr.husi.compose.TextFieldPreference
import fr.husi.compose.UIntegerTextField
import fr.husi.compose.material3.Text
import fr.husi.compose.preferenceGroup
import fr.husi.fmt.trojan_go.TrojanGoBean
import fr.husi.ktx.contentOrUnset
import fr.husi.resources.Res
import fr.husi.resources.action_shadowsocks
import fr.husi.resources.action_trojan_go
import fr.husi.resources.allow_insecure
import fr.husi.resources.allow_insecure_sum
import fr.husi.resources.compare_arrows
import fr.husi.resources.copyright
import fr.husi.resources.directions_boat
import fr.husi.resources.emoji_symbols
import fr.husi.resources.enable_mux
import fr.husi.resources.enc_method
import fr.husi.resources.encryption
import fr.husi.resources.enhanced_encryption
import fr.husi.resources.format_align_left
import fr.husi.resources.layers
import fr.husi.resources.low_priority
import fr.husi.resources.mux_number
import fr.husi.resources.mux_preference
import fr.husi.resources.mux_sum
import fr.husi.resources.network
import fr.husi.resources.plugin
import fr.husi.resources.profile_config
import fr.husi.resources.profile_name
import fr.husi.resources.proxy_cat
import fr.husi.resources.router
import fr.husi.resources.server_address
import fr.husi.resources.server_port
import fr.husi.resources.sni
import fr.husi.resources.udp
import fr.husi.resources.ws_host
import fr.husi.resources.ws_path
import fr.husi.ui.NavRoutes
import me.zhanghai.compose.preference.ListPreferenceType
import org.jetbrains.compose.resources.stringResource

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrojanGoSettingsScreen(
    profileId: Long,
    isSubscription: Boolean,
    onOpenConfigEditor: (NavRoutes.ConfigEditor) -> Unit,
    onResult: (updated: Boolean) -> Unit,
) {
    val viewModel: TrojanGoSettingsViewModel = profileEditorViewModel(
        profileId = profileId,
        isSubscription = isSubscription,
    ) {
        TrojanGoSettingsViewModel()
    }

    ProfileSettingsScreenScaffold<TrojanGoBean>(
        title = Res.string.profile_config,
        viewModel = viewModel,
        onResult = onResult,
        onOpenConfigEditor = onOpenConfigEditor,
    ) { uiState, _ ->
        trojanGoSettings(uiState as TrojanGoUiState, viewModel)
    }
}

private fun LazyListScope.trojanGoSettings(
    uiState: TrojanGoUiState,
    viewModel: TrojanGoSettingsViewModel,
) {
    val transportTypes = listOf("original", "ws")
    val encryptionTypes = listOf("none", "ss")
    val ssMethods = listOf("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305")

    preferenceGroup(key = "name") {
        TextFieldPreference(
            value = uiState.name,
            onValueChange = { viewModel.setName(it) },
            title = { Text(stringResource(Res.string.profile_name)) },
            textToValue = { it },
            icon = {
                MaskedIcon(Res.drawable.emoji_symbols, color = IconMaskColors.IconCyan)
            },
            summary = { Text(contentOrUnset(uiState.name)) },
            valueToText = { it },
        )
    }

    item("category_proxy") {
        PreferenceCategory(text = { Text(stringResource(Res.string.proxy_cat)) })
    }
    preferenceGroup(key = "address") {
        TextFieldPreference(
            value = uiState.address,
            onValueChange = { viewModel.setAddress(it) },
            title = { Text(stringResource(Res.string.server_address)) },
            textToValue = { it },
            icon = {
                MaskedIcon(Res.drawable.router, color = IconMaskColors.IconCyan)
            },
            summary = { Text(contentOrUnset(uiState.address)) },
            valueToText = { it },
        )
        TextFieldPreference(
            value = uiState.port,
            onValueChange = { viewModel.setPort(it) },
            title = { Text(stringResource(Res.string.server_port)) },
            textToValue = { it.toIntOrNull() ?: 443 },
            icon = {
                MaskedIcon(Res.drawable.directions_boat, color = IconMaskColors.IconCyan)
            },
            summary = { Text(uiState.port.toString()) },
            valueToText = { it.toString() },
            textField = { value, onValueChange, onOk ->
                UIntegerTextField(value, onValueChange, onOk, minValue = 1, maxValue = 65535)
            },
        )
        PasswordPreference(
            value = uiState.password,
            onValueChange = { viewModel.setPassword(it) },
        )
        TextFieldPreference(
            value = uiState.sni,
            onValueChange = { viewModel.setSni(it) },
            title = { Text(stringResource(Res.string.sni)) },
            textToValue = { it },
            icon = {
                MaskedIcon(Res.drawable.copyright, color = IconMaskColors.IconLightGreen)
            },
            summary = { Text(contentOrUnset(uiState.sni)) },
            valueToText = { it },
        )
        SwitchPreference(
            value = uiState.allowInsecure,
            onValueChange = { viewModel.setAllowInsecure(it) },
            title = { Text(stringResource(Res.string.allow_insecure)) },
            summary = { Text(stringResource(Res.string.allow_insecure_sum)) },
            icon = {
                MaskedIcon(Res.drawable.enhanced_encryption, color = IconMaskColors.IconCoral)
            },
        )
        SwitchPreference(
            value = uiState.udp,
            onValueChange = { viewModel.setUdp(it) },
            title = { Text(stringResource(Res.string.udp)) },
            icon = {
                MaskedIcon(Res.drawable.router, color = IconMaskColors.IconCoral)
            },
        )
    }

    item("category_transport") {
        PreferenceCategory(text = { Text(stringResource(Res.string.network)) })
    }
    preferenceGroup(key = "transport") {
        ListPreference(
            value = uiState.type,
            values = transportTypes,
            onValueChange = { viewModel.setType(it) },
            title = { Text(stringResource(Res.string.network)) },
            icon = {
                MaskedIcon(Res.drawable.compare_arrows, color = IconMaskColors.IconLightBlue)
            },
            summary = {
                Text(
                    when (uiState.type) {
                        "ws" -> "WebSocket (ws)"
                        else -> "Original (TCP)"
                    }
                )
            },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = {
                AnnotatedString(
                    when (it) {
                        "ws" -> "WebSocket (ws)"
                        else -> "Original (TCP)"
                    }
                )
            },
        )
        if (uiState.type == "ws") {
            TextFieldPreference(
                value = uiState.host,
                onValueChange = { viewModel.setHost(it) },
                title = { Text(stringResource(Res.string.ws_host)) },
                textToValue = { it },
                icon = {
                    MaskedIcon(Res.drawable.router, color = IconMaskColors.IconLightBlue)
                },
                summary = { Text(contentOrUnset(uiState.host)) },
                valueToText = { it },
            )
            TextFieldPreference(
                value = uiState.path,
                onValueChange = { viewModel.setPath(it) },
                title = { Text(stringResource(Res.string.ws_path)) },
                textToValue = { it },
                icon = {
                    MaskedIcon(Res.drawable.format_align_left, color = IconMaskColors.IconLightBlue)
                },
                summary = { Text(contentOrUnset(uiState.path)) },
                valueToText = { it },
            )
        }
        TextFieldPreference(
            value = uiState.plugin,
            onValueChange = { viewModel.setPlugin(it) },
            title = { Text(stringResource(Res.string.plugin)) },
            textToValue = { it },
            icon = {
                MaskedIcon(Res.drawable.router, color = IconMaskColors.IconLightBlue)
            },
            summary = { Text(contentOrUnset(uiState.plugin)) },
            valueToText = { it },
        )
    }

    item("category_shadowsocks") {
        PreferenceCategory(text = { Text(stringResource(Res.string.action_shadowsocks)) })
    }
    preferenceGroup(key = "shadowsocks") {
        ListPreference(
            value = uiState.encryption,
            values = encryptionTypes,
            onValueChange = { viewModel.setEncryption(it) },
            title = { Text(stringResource(Res.string.encryption)) },
            icon = {
                MaskedIcon(Res.drawable.layers, color = IconMaskColors.IconLavender)
            },
            summary = {
                Text(
                    when (uiState.encryption) {
                        "ss" -> "Shadowsocks"
                        else -> "None"
                    }
                )
            },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = {
                AnnotatedString(
                    when (it) {
                        "ss" -> "Shadowsocks"
                        else -> "None"
                    }
                )
            },
        )
        if (uiState.encryption == "ss") {
            ListPreference(
                value = uiState.ssMethod,
                values = ssMethods,
                onValueChange = { viewModel.setSSMethod(it) },
                title = { Text(stringResource(Res.string.enc_method)) },
                icon = {
                    MaskedIcon(Res.drawable.enhanced_encryption, color = IconMaskColors.IconLightBlue)
                },
                summary = { Text(contentOrUnset(uiState.ssMethod)) },
                type = ListPreferenceType.DROPDOWN_MENU,
                valueToText = { AnnotatedString(it) },
            )
            PasswordPreference(
                value = uiState.ssPassword,
                onValueChange = { viewModel.setSSPassword(it) },
            )
        }
    }

    item("category_mux") {
        PreferenceCategory(text = { Text(stringResource(Res.string.mux_preference)) })
    }
    preferenceGroup(key = "mux") {
        SwitchPreference(
            value = uiState.mux,
            onValueChange = { viewModel.setMux(it) },
            title = { Text(stringResource(Res.string.enable_mux)) },
            summary = { Text(stringResource(Res.string.mux_sum)) },
            icon = {
                MaskedIcon(Res.drawable.compare_arrows, color = IconMaskColors.IconLightOrange)
            },
        )
        if (uiState.mux) {
            TextFieldPreference(
                value = uiState.muxConcurrency,
                onValueChange = { viewModel.setMuxConcurrency(it) },
                title = { Text(stringResource(Res.string.mux_number)) },
                textToValue = { it.toIntOrNull() ?: 8 },
                icon = {
                    MaskedIcon(Res.drawable.low_priority, color = IconMaskColors.IconLightOrange)
                },
                summary = { Text(uiState.muxConcurrency.toString()) },
                valueToText = { it.toString() },
                textField = { value, onValueChange, onOk ->
                    UIntegerTextField(value, onValueChange, onOk, minValue = 1, maxValue = 128)
                },
            )
        }
    }
}

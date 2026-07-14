package fr.husi.ui.profile

import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.AnnotatedString
import fr.husi.compose.IconMaskColors
import fr.husi.compose.IconMaskShapes
import fr.husi.compose.ListPreference
import fr.husi.compose.MaskedIcon
import fr.husi.compose.MultilineTextField
import fr.husi.compose.PasswordPreference
import fr.husi.compose.PreferenceCategory
import fr.husi.compose.TextFieldPreference
import fr.husi.compose.UIntegerTextField
import fr.husi.compose.material3.Text
import fr.husi.compose.preferenceGroup
import fr.husi.fmt.mieru.MieruBean
import fr.husi.ktx.contentOrUnset
import fr.husi.ktx.intListN
import fr.husi.resources.Res
import fr.husi.resources.compare_arrows
import fr.husi.resources.directions_boat
import fr.husi.resources.disable
import fr.husi.resources.emoji_symbols
import fr.husi.resources.high
import fr.husi.resources.low
import fr.husi.resources.middle
import fr.husi.resources.mtu
import fr.husi.resources.mux_preference
import fr.husi.resources.pattern
import fr.husi.resources.person
import fr.husi.resources.profile_config
import fr.husi.resources.profile_name
import fr.husi.resources.protocol
import fr.husi.resources.proxy_cat
import fr.husi.resources.public_icon
import fr.husi.resources.router
import fr.husi.resources.server_address
import fr.husi.resources.server_port
import fr.husi.resources.settings
import fr.husi.resources.traffic_pattern
import fr.husi.resources.username
import fr.husi.ui.NavRoutes
import me.zhanghai.compose.preference.ListPreferenceType
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.stringResource

@Composable
fun MieruSettingsScreen(
    profileId: Long,
    isSubscription: Boolean,
    onResult: (updated: Boolean) -> Unit,
    onOpenConfigEditor: (NavRoutes.ConfigEditor) -> Unit,
) {
    val viewModel: MieruSettingsViewModel = profileEditorViewModel(
        profileId = profileId,
        isSubscription = isSubscription,
    ) {
        MieruSettingsViewModel()
    }

    ProfileSettingsScreenScaffold<MieruBean>(
        title = Res.string.profile_config,
        viewModel = viewModel,
        onResult = onResult,
        onOpenConfigEditor = onOpenConfigEditor,
    ) { uiState, _ ->
        mieruSettings(uiState as MieruUiState, viewModel)
    }
}

private fun LazyListScope.mieruSettings(
    uiState: MieruUiState,
    viewModel: MieruSettingsViewModel,
) {
    preferenceGroup(key = "name") {
        TextFieldPreference(
            value = uiState.name,
            onValueChange = { viewModel.setName(it) },
            title = { Text(stringResource(Res.string.profile_name)) },
            textToValue = { it },
            icon = {
                MaskedIcon(
                    Res.drawable.emoji_symbols,
                    color = IconMaskColors.IconCyan,
                )
            },
            summary = { Text(contentOrUnset(uiState.name)) },
            valueToText = { it },
        )
        PreferenceDivider()
        ListPreference(
            value = uiState.protocol,
            values = listOf(MieruBean.PROTOCOL_TCP, MieruBean.PROTOCOL_UDP),
            onValueChange = { viewModel.setProtocol(it) },
            title = { Text(stringResource(Res.string.protocol)) },
            icon = {
                MaskedIcon(Res.drawable.compare_arrows, color = IconMaskColors.IconCyan)
            },
            summary = { Text(uiState.protocol.uppercase()) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(it) },
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
            enabled = uiState.ports.isBlank(),
            icon = {
                MaskedIcon(
                    Res.drawable.directions_boat,
                    color = IconMaskColors.IconCyan,
                )
            },
            summary = { Text(uiState.port.toString()) },
            valueToText = { it.toString() },
            textField = { value, onValueChange, onOk ->
                UIntegerTextField(value, onValueChange, onOk)
            },
        )
        ListPreference(
            value = uiState.protocol,
            values = protocols,
            onValueChange = { viewModel.setProtocol(it) },
            title = { Text(stringResource(Res.string.protocol)) },
            icon = {
                MaskedIcon(
                    Res.drawable.compare_arrows,
                    color = IconMaskColors.IconLavender,
                )
            },
            summary = { Text(contentOrUnset(uiState.protocol.uppercase())) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(it) },
        )
        TextFieldPreference(
            value = uiState.username,
            onValueChange = { viewModel.setUsername(it) },
            title = { Text(stringResource(Res.string.username)) },
            textToValue = { it },
            icon = {
                MaskedIcon(
                    Res.drawable.person,
                    color = IconMaskColors.IconCyan,
                )
            },
            summary = { Text(contentOrUnset(uiState.username)) },
            valueToText = { it },
        )
        PasswordPreference(
            value = uiState.password,
            onValueChange = { viewModel.setPassword(it) },
        )
        if (uiState.protocol == MieruBean.PROTOCOL_UDP) {
            TextFieldPreference(
                value = uiState.mtu,
                onValueChange = { viewModel.setMtu(it) },
                title = { Text(stringResource(Res.string.mtu)) },
                textToValue = { it.toIntOrNull() ?: 1400 },
                icon = {
                    MaskedIcon(
                        Res.drawable.public_icon,
                        color = IconMaskColors.IconWarmGray,
                    )
                },
                summary = { Text(uiState.mtu.toString()) },
                valueToText = { it.toString() },
                textField = { value, onValueChange, onOk ->
                    UIntegerTextField(value, onValueChange, onOk)
                },
            )
            PreferenceDivider()
        }
        fun muxSummary(level: Int): StringResource = when (level) {
            1 -> Res.string.low
            2 -> Res.string.middle
            3 -> Res.string.high
            else -> Res.string.disable
        }
        ListPreference(
            value = uiState.muxNumber,
            values = intListN(4),
            onValueChange = { viewModel.setMuxNumber(it) },
            title = { Text(stringResource(Res.string.mux_preference)) },
            icon = {
                MaskedIcon(
                    Res.drawable.compare_arrows,
                    color = IconMaskColors.IconWarmGray,
                )
            },
            summary = { Text(stringResource(muxSummary(uiState.muxNumber))) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(stringResource(muxSummary(it))) },
        )
        PreferenceDivider()
        fun handshakeSummary(mode: Int): String = when (mode) {
            0 -> "DEFAULT"
            1 -> "STANDARD (1-RTT)"
            2 -> "NO_WAIT (0-RTT)"
            else -> "UNKNOWN"
        }
        ListPreference(
            value = uiState.handshakeMode,
            values = intListN(3),
            onValueChange = { viewModel.setHandshakeMode(it) },
            title = { Text("Handshake Mode") },
            icon = {
                MaskedIcon(
                    Res.drawable.compare_arrows,
                    color = IconMaskColors.IconWarmGray,
                )
            },
            summary = { Text(handshakeSummary(uiState.handshakeMode)) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(handshakeSummary(it)) },
        )
        PreferenceDivider()
        TextFieldPreference(
            value = uiState.heartbeatInterval,
            onValueChange = { viewModel.setHeartbeatInterval(it) },
            title = { Text("Heartbeat Interval") },
            textToValue = { it.toIntOrNull() ?: 0 },
            icon = {
                MaskedIcon(
                    Res.drawable.compare_arrows,
                    color = IconMaskColors.IconLightOrange,
                )
            },
            summary = { Text(if (uiState.heartbeatInterval > 0) "${uiState.heartbeatInterval}s" else "DEFAULT") },
            valueToText = { it.toString() },
            textField = { value, onValueChange, onOk ->
                UIntegerTextField(value, onValueChange, onOk)
            },
        )
        PreferenceDivider()
        TextFieldPreference(
            value = uiState.heartbeatJitter,
            onValueChange = { viewModel.setHeartbeatJitter(it) },
            title = { Text("Heartbeat Jitter") },
            textToValue = { it.toDoubleOrNull() ?: 0.0 },
            icon = {
                MaskedIcon(
                    Res.drawable.compare_arrows,
                    color = IconMaskColors.IconLightOrange,
                )
            },
            summary = { Text(if (uiState.heartbeatJitter > 0.0) uiState.heartbeatJitter.toString() else "DEFAULT") },
            valueToText = { it.toString() },
        )
        PreferenceDivider()
        TextFieldPreference(
            value = uiState.userHint,
            onValueChange = { viewModel.setUserHint(it) },
            title = { Text("User Hint") },
            textToValue = { it },
            icon = {
                MaskedIcon(
                    Res.drawable.person,
                    color = IconMaskColors.IconWarmGray,
                )
            },
            summary = { Text(contentOrUnset(uiState.userHint)) },
            valueToText = { it },
        )
        TextFieldPreference(
            value = uiState.trafficPattern,
            onValueChange = { viewModel.setTrafficPattern(it) },
            title = { Text(stringResource(Res.string.traffic_pattern)) },
            textToValue = { it },
            icon = {
                MaskedIcon(
                    Res.drawable.pattern,
                    color = IconMaskColors.IconWarmGray,
                )
            },
            summary = { Text(contentOrUnset(uiState.trafficPattern)) },
            valueToText = { it },
            textField = { value, onValueChange, onOk ->
                MultilineTextField(value, onValueChange, onOk)
            },
        )
    }
}

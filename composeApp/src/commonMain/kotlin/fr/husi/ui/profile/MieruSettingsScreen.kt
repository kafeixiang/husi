package fr.husi.ui.profile

import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material3.ExperimentalMaterial3Api
import fr.husi.compose.material3.Icon
import fr.husi.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.AnnotatedString
import fr.husi.compose.MultilineTextField
import fr.husi.compose.PasswordPreference
import fr.husi.compose.PreferenceCategory
import fr.husi.compose.UIntegerTextField
import fr.husi.ktx.contentOrUnset
import fr.husi.ktx.intListN
import fr.husi.resources.Res
import fr.husi.resources.compare_arrows
import fr.husi.resources.directions_boat
import fr.husi.resources.emoji_symbols
import fr.husi.resources.handshake_mode
import fr.husi.resources.handshake_mode_default
import fr.husi.resources.handshake_mode_no_wait
import fr.husi.resources.handshake_mode_standard
import fr.husi.resources.high
import fr.husi.resources.low
import fr.husi.resources.middle
import fr.husi.resources.mtu
import fr.husi.resources.mux_preference
import fr.husi.resources.not_set
import fr.husi.resources.off
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
import fr.husi.resources.traffic_pattern
import fr.husi.resources.user_hint
import fr.husi.resources.user_hint_sum
import fr.husi.resources.username
import fr.husi.ui.NavRoutes
import me.zhanghai.compose.preference.ListPreference
import me.zhanghai.compose.preference.ListPreferenceType
import me.zhanghai.compose.preference.SwitchPreference
import me.zhanghai.compose.preference.TextFieldPreference
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.resources.vectorResource

@OptIn(ExperimentalMaterial3Api::class)
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

    ProfileSettingsScreenScaffold(
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
    val protocols = listOf("TCP", "UDP")

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

    item("category_proxy") {
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
            summary = { Text(contentOrUnset(uiState.port)) },
            valueToText = { it },
        )
    }
    item("protocol") {
        ListPreference(
            value = uiState.protocol,
            values = protocols,
            onValueChange = { viewModel.setProtocol(it) },
            title = { Text(stringResource(Res.string.protocol)) },
            icon = { Icon(vectorResource(Res.drawable.compare_arrows), null) },
            summary = { Text(contentOrUnset(uiState.protocol.uppercase())) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(it) },
        )
    }
    item("username") {
        TextFieldPreference(
            value = uiState.username,
            onValueChange = { viewModel.setUsername(it) },
            title = { Text(stringResource(Res.string.username)) },
            textToValue = { it },
            icon = { Icon(vectorResource(Res.drawable.person), null) },
            summary = { Text(contentOrUnset(uiState.username)) },
            valueToText = { it },
        )
    }
    item("password") {
        PasswordPreference(
            value = uiState.password,
            onValueChange = { viewModel.setPassword(it) },
        )
    }
    if (uiState.protocol.uppercase() == "UDP") {
        item("mtu") {
            TextFieldPreference(
                value = uiState.mtu,
                onValueChange = { viewModel.setMtu(it) },
                title = { Text(stringResource(Res.string.mtu)) },
                textToValue = { it.toIntOrNull() ?: 1400 },
                icon = { Icon(vectorResource(Res.drawable.public_icon), null) },
                summary = { Text(contentOrUnset(uiState.mtu)) },
                valueToText = { it.toString() },
                textField = { value, onValueChange, onOk ->
                    UIntegerTextField(value, onValueChange, onOk)
                },
            )
        }
    }
    item("mux_number") {
        fun muxSummary(mux: Int): StringResource = when (mux) {
            0 -> Res.string.not_set
            1 -> Res.string.off
            2 -> Res.string.low
            3 -> Res.string.middle
            4 -> Res.string.high
            else -> Res.string.not_set
        }
        ListPreference(
            value = uiState.muxNumber,
            values = intListN(5),
            onValueChange = { viewModel.setMuxNumber(it) },
            title = { Text(stringResource(Res.string.mux_preference)) },
            icon = { Icon(vectorResource(Res.drawable.compare_arrows), null) },
            summary = { Text(stringResource(muxSummary(uiState.muxNumber))) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(stringResource(muxSummary(it))) },
        )
    }
    item("handshake_mode") {
        fun handshakeSummary(mode: Int): StringResource = when (mode) {
            0 -> Res.string.handshake_mode_default
            1 -> Res.string.handshake_mode_standard
            2 -> Res.string.handshake_mode_no_wait
            else -> Res.string.not_set
        }
        ListPreference(
            value = uiState.handshakeMode,
            values = intListN(3),
            onValueChange = { viewModel.setHandshakeMode(it) },
            title = { Text(stringResource(Res.string.handshake_mode)) },
            icon = { Icon(vectorResource(Res.drawable.compare_arrows), null) },
            summary = { Text(stringResource(handshakeSummary(uiState.handshakeMode))) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(stringResource(handshakeSummary(it))) },
        )
    }
    item("traffic_pattern") {
        TextFieldPreference(
            value = uiState.trafficPattern,
            onValueChange = viewModel::setTrafficPattern,
            title = { Text(stringResource(Res.string.traffic_pattern)) },
            textToValue = { it },
            icon = { Icon(vectorResource(Res.drawable.pattern), null) },
            summary = { Text(contentOrUnset(uiState.trafficPattern)) },
            valueToText = { it },
            textField = { value, onValueChange, onOk ->
                MultilineTextField(value, onValueChange, onOk)
            },
        )
    }
    item("user_hint") {
        SwitchPreference(
            value = uiState.userHint,
            onValueChange = { viewModel.setUserHint(it) },
            title = { Text(stringResource(Res.string.user_hint)) },
            icon = { Icon(vectorResource(Res.drawable.compare_arrows), null) },
            summary = { Text(stringResource(Res.string.user_hint_sum)) },
        )
    }
}

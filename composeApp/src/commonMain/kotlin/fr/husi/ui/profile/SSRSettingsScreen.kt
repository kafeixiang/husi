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
import fr.husi.compose.TextFieldPreference
import fr.husi.compose.UIntegerTextField
import fr.husi.compose.material3.Text
import fr.husi.compose.preferenceGroup
import fr.husi.fmt.ssr.SSRBean
import fr.husi.ktx.contentOrUnset
import fr.husi.resources.Res
import fr.husi.resources.action_ssr
import fr.husi.resources.directions_boat
import fr.husi.resources.emoji_symbols
import fr.husi.resources.enc_method
import fr.husi.resources.enhanced_encryption
import fr.husi.resources.obfs
import fr.husi.resources.obfs_param
import fr.husi.resources.profile_config
import fr.husi.resources.profile_name
import fr.husi.resources.protocol
import fr.husi.resources.protocol_param
import fr.husi.resources.proxy_cat
import fr.husi.resources.router
import fr.husi.resources.server_address
import fr.husi.resources.server_port
import fr.husi.resources.settings
import fr.husi.resources.type_specimen
import fr.husi.ui.NavRoutes
import me.zhanghai.compose.preference.ListPreferenceType
import org.jetbrains.compose.resources.stringResource

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SSRSettingsScreen(
    profileId: Long,
    isSubscription: Boolean,
    onOpenConfigEditor: (NavRoutes.ConfigEditor) -> Unit,
    onResult: (updated: Boolean) -> Unit,
) {
    val viewModel: SSRSettingsViewModel = profileEditorViewModel(
        profileId = profileId,
        isSubscription = isSubscription,
    ) {
        SSRSettingsViewModel()
    }

    ProfileSettingsScreenScaffold<SSRBean>(
        title = Res.string.profile_config,
        viewModel = viewModel,
        onResult = onResult,
        onOpenConfigEditor = onOpenConfigEditor,
    ) { uiState, _ ->
        ssrSettings(uiState as SSRUiState, viewModel)
    }
}

private fun LazyListScope.ssrSettings(
    uiState: SSRUiState,
    viewModel: SSRSettingsViewModel,
) {
    val encryptionMethods = listOf(
        "none",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "aes-128-cfb8",
        "aes-192-cfb8",
        "aes-256-cfb8",
        "aes-128-ofb",
        "aes-192-ofb",
        "aes-256-ofb",
        "camellia-128-cfb",
        "camellia-192-cfb",
        "camellia-256-cfb",
        "camellia-128-cfb8",
        "camellia-192-cfb8",
        "camellia-256-cfb8",
        "rc4-md5",
        "rc4-md5-6",
        "rc4",
        "bf-cfb",
        "cast5-cfb",
        "des-cfb",
        "idea-cfb",
        "rc2-cfb",
        "seed-cfb",
        "chacha20-ietf",
        "xchacha20",
        "chacha20",
        "xsalsa20",
        "salsa20",
        "table",
        "rabbit",
        "hc128",
        "zuc128",
    )
    val protocols = listOf(
        "origin",
        "auth_sha1_v4",
        "auth_aes128_sha1",
        "auth_aes128_md5",
        "auth_chain_a",
        "auth_chain_b",
    )
    val obfses = listOf(
        "plain",
        "http_simple",
        "http_post",
        "tls1.2_ticket_auth",
        "tls1.2_ticket_fastauth",
        "random_head",
    )

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
            textToValue = { it.toIntOrNull() ?: 8388 },
            icon = {
                MaskedIcon(
                    Res.drawable.directions_boat,
                    color = IconMaskColors.IconCyan,
                )
            },
            summary = { Text(uiState.port.toString()) },
            valueToText = { it.toString() },
            textField = { value, onValueChange, onOk ->
                UIntegerTextField(value, onValueChange, onOk, minValue = 1, maxValue = 65535)
            },
        )
        ListPreference(
            value = uiState.method,
            values = encryptionMethods,
            onValueChange = { viewModel.setMethod(it) },
            title = { Text(stringResource(Res.string.enc_method)) },
            icon = {
                MaskedIcon(
                    Res.drawable.enhanced_encryption,
                    color = IconMaskColors.IconLightBlue,
                )
            },
            summary = { Text(contentOrUnset(uiState.method)) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(it) },
        )
        PasswordPreference(
            value = uiState.password,
            onValueChange = { viewModel.setPassword(it) },
        )
    }

    item("category_ssr") {
        PreferenceCategory(text = { Text(stringResource(Res.string.action_ssr)) })
    }
    preferenceGroup(key = "ssr") {
        ListPreference(
            value = uiState.protocol,
            values = protocols,
            onValueChange = { viewModel.setProtocol(it) },
            title = { Text(stringResource(Res.string.protocol)) },
            icon = {
                MaskedIcon(
                    Res.drawable.type_specimen,
                    color = IconMaskColors.IconLightGreen,
                )
            },
            summary = { Text(contentOrUnset(uiState.protocol)) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(it) },
        )
        TextFieldPreference(
            value = uiState.protocolParam,
            onValueChange = { viewModel.setProtocolParam(it) },
            title = { Text(stringResource(Res.string.protocol_param)) },
            textToValue = { it },
            icon = {
                MaskedIcon(
                    Res.drawable.settings,
                    color = IconMaskColors.IconWarmGray,
                )
            },
            summary = { Text(contentOrUnset(uiState.protocolParam)) },
            valueToText = { it },
        )
        ListPreference(
            value = uiState.obfs,
            values = obfses,
            onValueChange = { viewModel.setObfs(it) },
            title = { Text(stringResource(Res.string.obfs)) },
            icon = {
                MaskedIcon(
                    Res.drawable.type_specimen,
                    color = IconMaskColors.IconLavender,
                )
            },
            summary = { Text(contentOrUnset(uiState.obfs)) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(it) },
        )
        TextFieldPreference(
            value = uiState.obfsParam,
            onValueChange = { viewModel.setObfsParam(it) },
            title = { Text(stringResource(Res.string.obfs_param)) },
            textToValue = { it },
            icon = {
                MaskedIcon(
                    Res.drawable.settings,
                    color = IconMaskColors.IconWarmGray,
                )
            },
            summary = { Text(contentOrUnset(uiState.obfsParam)) },
            valueToText = { it },
        )
    }
}

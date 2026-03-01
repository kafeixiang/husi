package fr.husi.ui.profile

import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.text.AnnotatedString
import androidx.lifecycle.viewmodel.compose.viewModel
import fr.husi.compose.PasswordPreference
import fr.husi.compose.PreferenceCategory
import fr.husi.compose.UIntegerTextField
import fr.husi.fmt.ssr.SSRBean
import fr.husi.ktx.contentOrUnset
import fr.husi.resources.Res
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
import me.zhanghai.compose.preference.ListPreference
import me.zhanghai.compose.preference.ListPreferenceType
import me.zhanghai.compose.preference.TextFieldPreference
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.resources.vectorResource

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SSRSettingsScreen(
    profileId: Long,
    isSubscription: Boolean,
    onOpenConfigEditor: (NavRoutes.ConfigEditor) -> Unit,
    onResult: (updated: Boolean) -> Unit,
) {
    val viewModel: SSRSettingsViewModel = viewModel { SSRSettingsViewModel() }
    LaunchedEffect(profileId, isSubscription) {
        viewModel.initialize(profileId, isSubscription)
    }

    ProfileSettingsScreenScaffold<SSRBean>(
        title = Res.string.profile_config,
        viewModel = viewModel,
        onResult = onResult,
        onOpenConfigEditor = onOpenConfigEditor,
    ) { uiState, scrollTo ->
        ssrSettings(uiState as SSRUiState, viewModel, scrollTo)
    }
}

private fun LazyListScope.ssrSettings(
    uiState: SSRUiState,
    viewModel: SSRSettingsViewModel,
    scrollTo: (key: String) -> Unit,
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
            textToValue = { it.toIntOrNull() ?: 8388 },
            icon = { Icon(vectorResource(Res.drawable.directions_boat), null) },
            summary = { Text(contentOrUnset(uiState.port)) },
            valueToText = { it.toString() },
            textField = { value, onValueChange, onOk ->
                UIntegerTextField(value, onValueChange, onOk)
            },
        )
    }
    item("method") {
        ListPreference(
            value = uiState.method,
            values = encryptionMethods,
            onValueChange = { viewModel.setMethod(it) },
            title = { Text(stringResource(Res.string.enc_method)) },
            icon = { Icon(vectorResource(Res.drawable.enhanced_encryption), null) },
            summary = { Text(contentOrUnset(uiState.method)) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(it) },
        )
    }
    item("password") {
        PasswordPreference(
            value = uiState.password,
            onValueChange = { viewModel.setPassword(it) },
        )
    }

    item("protocol") {
        ListPreference(
            value = uiState.protocol,
            values = protocols,
            onValueChange = { viewModel.setProtocol(it) },
            title = { Text(stringResource(Res.string.protocol)) },
            icon = { Icon(vectorResource(Res.drawable.type_specimen), null) },
            summary = { Text(contentOrUnset(uiState.protocol)) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(it) },
        )
    }
    item("protocol_param") {
        TextFieldPreference(
            value = uiState.protocolParam,
            onValueChange = { viewModel.setProtocolParam(it) },
            title = { Text(stringResource(Res.string.protocol_param)) },
            textToValue = { it },
            icon = { Icon(vectorResource(Res.drawable.settings), null) },
            summary = { Text(contentOrUnset(uiState.protocolParam)) },
            valueToText = { it },
        )
    }
    item("obfs") {
        ListPreference(
            value = uiState.obfs,
            values = obfses,
            onValueChange = { viewModel.setObfs(it) },
            title = { Text(stringResource(Res.string.obfs)) },
            icon = { Icon(vectorResource(Res.drawable.type_specimen), null) },
            summary = { Text(contentOrUnset(uiState.obfs)) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(it) },
        )
    }
    item("obfs_param") {
        TextFieldPreference(
            value = uiState.obfsParam,
            onValueChange = { viewModel.setObfsParam(it) },
            title = { Text(stringResource(Res.string.obfs_param)) },
            textToValue = { it },
            icon = { Icon(vectorResource(Res.drawable.settings), null) },
            summary = { Text(contentOrUnset(uiState.obfsParam)) },
            valueToText = { it },
        )
    }
}

package fr.husi.ui.profile

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import fr.husi.compose.PreferenceCategory
import fr.husi.compose.UIntegerTextField
import fr.husi.fmt.ssr.supportedShadowsocksRMethod
import fr.husi.fmt.ssr.supportedShadowsocksRObfs
import fr.husi.fmt.ssr.supportedShadowsocksRProtocol
import fr.husi.ktx.contentOrUnset
import fr.husi.resources.Res
import fr.husi.resources.directions_boat
import fr.husi.resources.emoji_symbols
import fr.husi.resources.enc_method
import fr.husi.resources.enhanced_encryption
import fr.husi.resources.network
import fr.husi.resources.obfs
import fr.husi.resources.obfs_param
import fr.husi.resources.password
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
import fr.husi.resources.vpn_key
import me.zhanghai.compose.preference.ListPreference
import me.zhanghai.compose.preference.ListPreferenceType
import me.zhanghai.compose.preference.TextFieldPreference
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.resources.vectorResource

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShadowsocksRSettingsScreen(
    profileId: Long,
    isSubscription: Boolean,
    onResult: (updated: Boolean) -> Unit,
) {
    val viewModel: ShadowsocksRSettingsViewModel = viewModel { ShadowsocksRSettingsViewModel() }
    LaunchedEffect(profileId, isSubscription) {
        viewModel.initialize(profileId, isSubscription)
    }

    ProfileSettingsScreenScaffold(
        title = Res.string.profile_config,
        viewModel = viewModel,
        onResult = onResult,
    ) { scope, uiState, scrollTo ->
        scope.shadowsocksRSettings(uiState as ShadowsocksRUiState, viewModel, scrollTo)
    }
}

private fun LazyListScope.shadowsocksRSettings(
    uiState: ShadowsocksRUiState,
    viewModel: ShadowsocksRSettingsViewModel,
    scrollTo: (key: String) -> Unit,
) {
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
            summary = { Text(contentOrUnset(uiState.port.toString())) },
            valueToText = { it.toString() },
            textField = { value, onValueChange, onOk ->
                UIntegerTextField(value, onValueChange, onOk)
            },
        )
    }
    item("method") {
        ListPreference(
            value = uiState.method,
            values = supportedShadowsocksRMethod.toList(),
            onValueChange = { viewModel.setMethod(it) },
            title = { Text(stringResource(Res.string.enc_method)) },
            icon = { Icon(vectorResource(Res.drawable.enhanced_encryption), null) },
            summary = { Text(contentOrUnset(uiState.method)) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(it) },
        )
    }
    item("password") {
        TextFieldPreference(
            value = uiState.password,
            onValueChange = { viewModel.setPassword(it) },
            title = { Text(stringResource(Res.string.password)) },
            textToValue = { it },
            icon = { Icon(vectorResource(Res.drawable.vpn_key), null) },
            summary = { Text(contentOrUnset(uiState.password)) },
            valueToText = { it },
        )
    }

    item("network") {
        ListPreference(
            value = uiState.network,
            values = listOf("tcp", "udp", "tcp,udp"),
            onValueChange = { viewModel.setNetwork(it) },
            title = { Text(stringResource(Res.string.network)) },
            icon = { Icon(vectorResource(Res.drawable.router), null) },
            summary = { Text(uiState.network) },
            type = ListPreferenceType.DROPDOWN_MENU,
            valueToText = { AnnotatedString(it) },
        )
    }

    item("category_protocol") {
        PreferenceCategory(text = { Text(stringResource(Res.string.protocol)) })
    }
    item("protocol") {
        ListPreference(
            value = uiState.protocol,
            values = supportedShadowsocksRProtocol.toList(),
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
            icon = { Spacer(Modifier.size(24.dp)) },
            summary = { Text(contentOrUnset(uiState.protocolParam)) },
            valueToText = { it },
        )
    }

    item("category_obfs") {
        PreferenceCategory(text = { Text(stringResource(Res.string.obfs)) })
    }
    item("obfs") {
        ListPreference(
            value = uiState.obfs,
            values = supportedShadowsocksRObfs.toList(),
            onValueChange = { viewModel.setObfs(it) },
            title = { Text(stringResource(Res.string.obfs)) },
            icon = { Icon(vectorResource(Res.drawable.settings), null) },
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
            icon = { Spacer(Modifier.size(24.dp)) },
            summary = { Text(contentOrUnset(uiState.obfsParam)) },
            valueToText = { it },
        )
    }
}

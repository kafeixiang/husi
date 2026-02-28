package fr.husi.ui.profile

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.windowInsetsBottomHeight
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.AnnotatedString
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import fr.husi.compose.SimpleIconButton
import fr.husi.compose.paddingExceptBottom
import fr.husi.plugin.PluginOptions
import fr.husi.resources.Res
import fr.husi.resources.*
import me.zhanghai.compose.preference.ListPreference
import me.zhanghai.compose.preference.ListPreferenceType
import me.zhanghai.compose.preference.ProvidePreferenceLocals
import me.zhanghai.compose.preference.TextFieldPreference
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.resources.vectorResource

@Stable
internal class ObfsLocalViewModel : ViewModel() {
    var obfs by mutableStateOf("http")
    var host by mutableStateOf("cloudfront.net")
    private var lastConfig: String? = null

    fun init(config: String) {
        if (lastConfig == config) return
        lastConfig = config
        val options = PluginOptions(config)
        obfs = when {
            options["mode"] == "http" -> "http"
            options["obfs"] == "tls" -> "tls"
            else -> "http"
        }
        host = options["host"] ?: options["obfs-host"] ?: "cloudfront.net"
    }

    fun getResult(): String = PluginOptions().apply {
        put("obfs", obfs)
        if (host != "cloudfront.net") {
            put("obfs-host", host)
        }
    }.toString()
}

@Stable
internal class V2RayPluginViewModel : ViewModel() {
    var mode by mutableStateOf("websocket-http")
    var host by mutableStateOf("cloudfront.com")
    var path by mutableStateOf("/")
    var mux by mutableStateOf("1")
    var serviceName by mutableStateOf("")
    var certRaw by mutableStateOf("")
    var loglevel by mutableStateOf("warning")
    private var lastConfig: String? = null

    fun init(config: String) {
        if (lastConfig == config) return
        lastConfig = config
        val options = PluginOptions(config)
        mode = when {
            (options["mode"] ?: "websocket") == "quic" -> "quic-tls"
            options["mode"] == null && "tls" in options -> "websocket-tls"
            options["mode"] == "grpc" && "tls" !in options -> "grpc"
            options["mode"] == "grpc" && "tls" in options -> "grpc-tls"
            else -> "websocket-http"
        }
        host = options["host"] ?: "cloudfront.com"
        path = options["path"] ?: "/"
        mux = options["mux"] ?: "1"
        serviceName = options["serviceName"] ?: ""
        certRaw = options["certRaw"] ?: ""
        loglevel = options["loglevel"] ?: "warning"
    }

    fun readMode(value: String): Pair<String?, Boolean> = when (value) {
        "websocket-http" -> Pair(null, false)
        "websocket-tls" -> Pair(null, true)
        "quic-tls" -> Pair("quic", false)
        "grpc" -> Pair("grpc", false)
        "grpc-tls" -> Pair("grpc", true)
        else -> Pair(null, false)
    }

    fun getResult(): String {
        val (m, tls) = readMode(mode)
        return PluginOptions().apply {
            if (m != null) put("mode", m)
            if (tls) put("tls", null)
            if (host != "cloudfront.com") put("host", host)
            if (path != "/") put("path", path)
            if (mux != "1") put("mux", mux)
            if (m == "grpc" && serviceName.isNotEmpty()) put("serviceName", serviceName)
            if (certRaw.isNotEmpty()) put("certRaw", certRaw.replace("\n", ""))
            if (loglevel != "warning") put("loglevel", loglevel)
        }.toString()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ObfsLocalConfigScreen(
    initialConfig: String,
    onSave: (String) -> Unit,
    onBack: () -> Unit,
) {
    val viewModel: ObfsLocalViewModel = viewModel { ObfsLocalViewModel() }
    LaunchedEffect(initialConfig) {
        viewModel.init(initialConfig)
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(Res.string.plugin_simple_obfuscation)) },
                navigationIcon = {
                    SimpleIconButton(
                        imageVector = vectorResource(Res.drawable.arrow_back),
                        contentDescription = stringResource(Res.string.back),
                        onClick = onBack,
                    )
                },
                actions = {
                    SimpleIconButton(
                        imageVector = vectorResource(Res.drawable.done),
                        contentDescription = stringResource(Res.string.apply),
                        onClick = {
                            onSave(viewModel.getResult())
                        },
                    )
                },
            )
        },
    ) { innerPadding ->
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .paddingExceptBottom(innerPadding),
            color = MaterialTheme.colorScheme.background
        ) {
            ProvidePreferenceLocals {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    item {
                        ListPreference(
                            value = viewModel.obfs,
                            values = listOf("http", "tls"),
                            onValueChange = { viewModel.obfs = it },
                            title = { Text(stringResource(Res.string.obfs)) },
                            summary = { Text(viewModel.obfs) },
                            type = ListPreferenceType.DROPDOWN_MENU,
                            valueToText = { AnnotatedString(it) },
                        )
                    }
                    item {
                        TextFieldPreference(
                            value = viewModel.host,
                            onValueChange = { viewModel.host = it },
                            title = { Text(stringResource(Res.string.obfs_param)) },
                            summary = { Text(viewModel.host) },
                            textToValue = { it },
                            valueToText = { it },
                        )
                    }
                    item {
                        Spacer(Modifier.windowInsetsBottomHeight(WindowInsets.navigationBars))
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun V2RayPluginConfigScreen(
    initialConfig: String,
    onSave: (String) -> Unit,
    onBack: () -> Unit,
) {
    val viewModel: V2RayPluginViewModel = viewModel { V2RayPluginViewModel() }
    LaunchedEffect(initialConfig) {
        viewModel.init(initialConfig)
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(Res.string.plugin_v2ray_plugin)) },
                navigationIcon = {
                    SimpleIconButton(
                        imageVector = vectorResource(Res.drawable.arrow_back),
                        contentDescription = stringResource(Res.string.back),
                        onClick = onBack,
                    )
                },
                actions = {
                    SimpleIconButton(
                        imageVector = vectorResource(Res.drawable.done),
                        contentDescription = stringResource(Res.string.apply),
                        onClick = {
                            onSave(viewModel.getResult())
                        },
                    )
                },
            )
        },
    ) { innerPadding ->
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .paddingExceptBottom(innerPadding),
            color = MaterialTheme.colorScheme.background
        ) {
            ProvidePreferenceLocals {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    item {
                        ListPreference(
                            value = viewModel.mode,
                            values = listOf("websocket-http", "websocket-tls", "quic-tls", "grpc", "grpc-tls"),
                            onValueChange = { viewModel.mode = it },
                            title = { Text(stringResource(Res.string.network)) },
                            summary = { Text(viewModel.mode) },
                            type = ListPreferenceType.DROPDOWN_MENU,
                            valueToText = { AnnotatedString(it) },
                        )
                    }
                    item {
                        TextFieldPreference(
                            value = viewModel.host,
                            onValueChange = { viewModel.host = it },
                            title = { Text(stringResource(Res.string.ws_host)) },
                            summary = { Text(viewModel.host) },
                            textToValue = { it },
                            valueToText = { it },
                        )
                    }
                    item {
                        val (m, _) = viewModel.readMode(viewModel.mode)
                        TextFieldPreference(
                            value = viewModel.path,
                            onValueChange = { viewModel.path = it },
                            title = { Text(stringResource(Res.string.ws_path)) },
                            summary = { Text(viewModel.path) },
                            textToValue = { it },
                            valueToText = { it },
                            enabled = m == null,
                        )
                    }
                    item {
                        val (m, _) = viewModel.readMode(viewModel.mode)
                        TextFieldPreference(
                            value = viewModel.serviceName,
                            onValueChange = { viewModel.serviceName = it },
                            title = { Text(stringResource(Res.string.grpc_service_name)) },
                            summary = { Text(viewModel.serviceName) },
                            textToValue = { it },
                            valueToText = { it },
                            enabled = m == "grpc",
                        )
                    }
                    item {
                        val (m, _) = viewModel.readMode(viewModel.mode)
                        TextFieldPreference(
                            value = viewModel.mux,
                            onValueChange = { viewModel.mux = it },
                            title = { Text(stringResource(Res.string.mux_strategy)) },
                            summary = { Text(viewModel.mux) },
                            textToValue = { it },
                            valueToText = { it },
                            enabled = m == null,
                        )
                    }
                    item {
                        val (m, tls) = viewModel.readMode(viewModel.mode)
                        TextFieldPreference(
                            value = viewModel.certRaw,
                            onValueChange = { viewModel.certRaw = it },
                            title = { Text(stringResource(Res.string.certificates)) },
                            summary = { Text(if (viewModel.certRaw.isBlank()) stringResource(Res.string.plugin_not_set) else stringResource(Res.string.plugin_set)) },
                            textToValue = { it },
                            valueToText = { it },
                            enabled = (m == null && tls) || (m == "quic") || (m == "grpc" && tls),
                        )
                    }
                    item {
                        ListPreference(
                            value = viewModel.loglevel,
                            values = listOf("debug", "info", "warning", "error", "none"),
                            onValueChange = { viewModel.loglevel = it },
                            title = { Text(stringResource(Res.string.log_level)) },
                            summary = { Text(viewModel.loglevel) },
                            type = ListPreferenceType.DROPDOWN_MENU,
                            valueToText = { AnnotatedString(it) },
                        )
                    }
                    item {
                        Spacer(Modifier.windowInsetsBottomHeight(WindowInsets.navigationBars))
                    }
                }
            }
        }
    }
}

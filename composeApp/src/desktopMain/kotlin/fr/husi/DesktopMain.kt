package fr.husi

import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Tray
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.isTraySupported
import androidx.compose.ui.window.rememberTrayState
import androidx.compose.ui.window.rememberWindowState
import fr.husi.bg.BackendState
import fr.husi.bg.DeepLinkDispatcher
import fr.husi.bg.ServiceState
import fr.husi.compose.theme.AppTheme
import fr.husi.database.DataStore
import fr.husi.di.initHusiKoin
import fr.husi.ktx.Logs
import fr.husi.ktx.blankAsNull
import fr.husi.ktx.exitApplication
import fr.husi.ktx.toStringIterator
import fr.husi.libcore.Client
import fr.husi.libcore.Libcore
import fr.husi.libcore.loadCA
import fr.husi.platform.PlatformInfo
import fr.husi.repository.DesktopRepository
import fr.husi.repository.resolveDesktopRepository
import fr.husi.resources.Res
import fr.husi.resources.app_name
import fr.husi.resources.close
import fr.husi.resources.exit
import fr.husi.resources.ic_service_active
import fr.husi.resources.instance_already_running
import fr.husi.resources.instance_already_running_title
import fr.husi.resources.service_mode
import fr.husi.resources.service_mode_proxy
import fr.husi.resources.service_mode_vpn
import fr.husi.resources.start
import fr.husi.resources.stop
import fr.husi.ui.MainScreen
import fr.husi.utils.CrashHandler
import fr.husi.utils.copyBundledRuleSetAssetsIfNeeded
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.optional
import kotlinx.cli.vararg
import kotlinx.coroutines.runBlocking
import org.jetbrains.compose.resources.painterResource
import org.jetbrains.compose.resources.stringResource
import java.awt.Desktop
import java.io.File
import javax.swing.JOptionPane
import kotlin.system.exitProcess

private const val MIN_LOG_LEVEL = 0
private const val MAX_LOG_LEVEL = 6
private const val PreferenceNodePropertyName = "me.zhanghai.compose.preference.node"
private const val PreferenceNodeName = "/fr/husi/preference"

fun main(args: Array<String>) {
    registerMacOSOpenUriHandler()
    val desktopArgs = parseDesktopStartupArgs(args)
    initDesktopRuntime(desktopArgs)
    for (link in desktopArgs.deepLinks) {
        DeepLinkDispatcher.emit(link)
    }

    application {
        val repository = resolveDesktopRepository()
        var windowVisible by remember { mutableStateOf(true) }

        val trayState = rememberTrayState()
        val windowState = rememberWindowState(size = DpSize(1200.dp, 800.dp))

        fun openWindow() {
            windowVisible = true
            windowState.isMinimized = false
        }

        fun exitGracefully() {
            runCatching {
                runBlocking {
                    repository.stopService()
                }
            }
            exitApplication()
        }

        DesktopResourceEnvironmentFix {
            val supportTray = remember { isTraySupported }
            if (supportTray) {
                // In fact, whether on macOS, Windows, or Linux, the advanced tray consistently throws "java.lang.UnsupportedOperationException: java.awt.Menu doesn't support mnemonic."
                val supportAdvancedTray = false
                Tray(
                    icon = painterResource(Res.drawable.ic_service_active),
                    state = trayState,
                    tooltip = stringResource(Res.string.app_name),
                    onAction = ::openWindow,
                ) {
                    val serviceStatus by BackendState.status.collectAsState()
                    Item(
                        text = serviceStatus.profileName ?: stringResource(Res.string.app_name),
                        mnemonic = if (supportAdvancedTray) {
                            'O'
                        } else {
                            null
                        },
                    ) {
                        openWindow()
                    }
                    Item(
                        text = stringResource(
                            if (serviceStatus.state == ServiceState.Connected) {
                                Res.string.stop
                            } else {
                                Res.string.start
                            },
                        ),
                        enabled = serviceStatus.state == ServiceState.Connected
                                || serviceStatus.state == ServiceState.Stopped
                                || serviceStatus.state == ServiceState.Idle,
                    ) {
                        when (serviceStatus.state) {
                            ServiceState.Stopped -> repository.startService()
                            ServiceState.Idle, ServiceState.Connected -> repository.stopService()
                            else -> {}
                        }
                    }
                    Menu(
                        text = stringResource(Res.string.service_mode),
                    ) {
                        val serviceMode by DataStore.configurationStore
                            .stringFlow(Key.SERVICE_MODE, Key.MODE_VPN)
                            .collectAsState(Key.MODE_VPN)
                        CheckboxItem(
                            text = stringResource(Res.string.service_mode_proxy),
                            checked = serviceMode == Key.MODE_PROXY,
                        ) {
                            if (serviceMode != Key.MODE_PROXY) {
                                DataStore.serviceMode = Key.MODE_PROXY
                                repository.reloadService()
                            }
                        }
                        CheckboxItem(
                            text = stringResource(Res.string.service_mode_vpn),
                            checked = serviceMode == Key.MODE_VPN,
                        ) {
                            if (serviceMode != Key.MODE_VPN) {
                                DataStore.serviceMode = Key.MODE_VPN
                                repository.reloadService()
                            }
                        }
                    }
                    Item(
                        text = stringResource(Res.string.exit),
                        icon = if (supportAdvancedTray) {
                            painterResource(Res.drawable.close)
                        } else {
                            null
                        },
                        mnemonic = if (supportAdvancedTray) {
                            'E'
                        } else {
                            null
                        },
                        onClick = ::exitGracefully,
                    )
                }
            }

            Window(
                onCloseRequest = { windowVisible = false },
                state = windowState,
                visible = windowVisible,
                title = stringResource(Res.string.app_name),
                icon = if (PlatformInfo.isMacOs) {
                    // Already set native dock icon in launcher
                    null
                } else {
                    painterResource(Res.drawable.ic_service_active)
                },
            ) {
                AppTheme {
                    MainScreen(moveToBackground = {})
                }
            }
        }
    }
}

private fun registerMacOSOpenUriHandler() {
    if (!PlatformInfo.isMacOs) return
    try {
        val desktop = Desktop.getDesktop()
        if (!desktop.isSupported(Desktop.Action.APP_OPEN_URI)) return
        desktop.setOpenURIHandler { event ->
            DeepLinkDispatcher.emit(event.uri.toString())
        }
    } catch (e: Exception) {
        Logs.w("register macOS open-uri handler", e)
    }
}

private data class DesktopStartupArgs(
    val baseDir: File?,
    val logLevelOverride: Int?,
    val many: Boolean,
    val deepLinks: List<String>,
)

private fun parseDesktopStartupArgs(args: Array<String>): DesktopStartupArgs {
    val parser = ArgParser("husi")
    val baseDir by parser.option(
        type = ArgType.String,
        fullName = "dir",
        shortName = "d",
        description = "Data directory",
    )
    val logLevel by parser.option(
        type = ArgType.Int,
        fullName = "log-level",
        shortName = "l",
        description = "Log level override (0-6)",
    )
    val many by parser.option(
        type = ArgType.Boolean,
        fullName = "many",
        shortName = "m",
        description = "Ignore exist instance",
    )
    val links by parser.argument(
        type = ArgType.String,
        fullName = "deep-link",
        description = "Deep links",
    ).vararg().optional()
    parser.parse(args)
    return DesktopStartupArgs(
        baseDir = baseDir?.blankAsNull()?.let(::File),
        logLevelOverride = logLevel?.takeIf { it in MIN_LOG_LEVEL..MAX_LOG_LEVEL },
        many = many == true,
        deepLinks = links,
    )
}

private fun initDesktopRuntime(startupArgs: DesktopStartupArgs) {
    // Fix jar package
    System.setProperty(PreferenceNodePropertyName, PreferenceNodeName)

    val baseDir = startupArgs.baseDir
        ?: File(System.getProperty("user.home"), ".config").resolve("husi")
    baseDir.mkdirs()
    val repository = DesktopRepository(baseDir)
    initHusiKoin(repository)
    val filesDir = repository.filesDir.absolutePath + "/"

    if (!startupArgs.many) {
        when (checkExistingInstance(filesDir, startupArgs.deepLinks)) {
            ExistingInstanceCheckResult.NotFound -> Unit
            ExistingInstanceCheckResult.ExistsNoDeepLink,
            ExistingInstanceCheckResult.ExistsForwardFailed,
                -> warnForExistInstanceAndExit(filesDir)

            ExistingInstanceCheckResult.ExistsForwarded -> exitApplication()
        }
    }

    Thread.setDefaultUncaughtExceptionHandler(CrashHandler)

    val cacheDir = repository.cacheDir.absolutePath + "/"
    val externalAssetsDir = repository.externalAssetsDir.absolutePath + "/"

    val rulesProvider = DataStore.rulesProvider
    val isOfficialProvider = rulesProvider == RuleProvider.OFFICIAL
    if (isOfficialProvider) {
        runBlocking {
            copyBundledRuleSetAssetsIfNeeded()
        }
    }
    Libcore.initCore(
        true,
        cacheDir,
        filesDir,
        externalAssetsDir,
        DataStore.logMaxLine,
        startupArgs.logLevelOverride ?: DataStore.logLevel,
        isOfficialProvider,
        DataStore.isExpert,
    )
    loadCA(DataStore.certProvider)
    repository.boxService?.start()
}

private enum class ExistingInstanceCheckResult {
    NotFound,
    ExistsNoDeepLink,
    ExistsForwarded,
    ExistsForwardFailed,
}

private fun checkExistingInstance(
    socketBasePath: String,
    deepLinks: List<String>,
): ExistingInstanceCheckResult {
    val client = runCatching {
        Libcore.newClient(socketBasePath)
    }.getOrNull() ?: return ExistingInstanceCheckResult.NotFound
    return try {
        if (deepLinks.isEmpty()) {
            ExistingInstanceCheckResult.ExistsNoDeepLink
        } else if (forwardDeepLinks(client, deepLinks)) {
            ExistingInstanceCheckResult.ExistsForwarded
        } else {
            ExistingInstanceCheckResult.ExistsForwardFailed
        }
    } finally {
        client.close()
    }
}

private fun forwardDeepLinks(client: Client, deepLinks: List<String>): Boolean {
    return runCatching {
        client.importDeepLinks(deepLinks.toStringIterator(deepLinks.size))
    }.onFailure {
        Logs.e(it)
    }.isSuccess
}

private fun warnForExistInstanceAndExit(socketBasePath: String) {
    val repository = resolveDesktopRepository()
    val socketPath = socketBasePath + Libcore.Socket
    val title = runBlocking { repository.getString(Res.string.instance_already_running_title) }
    val message = runBlocking { repository.getString(Res.string.instance_already_running, socketPath) }
    try {
        JOptionPane.showMessageDialog(
            null,
            message,
            title,
            JOptionPane.WARNING_MESSAGE,
        )
    } catch (e: Exception) {
        System.err.println("$title: $message")
        System.err.println(e.message)
    }
    exitProcess(1)
}

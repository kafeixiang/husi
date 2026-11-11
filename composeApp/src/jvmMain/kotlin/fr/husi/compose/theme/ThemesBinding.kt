package fr.husi.compose.theme

import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import fr.husi.compose.LocalThemedTopBarEnabled
import fr.husi.compose.collectAsStateWithLifecycle
import fr.husi.database.DataStore

@Composable
fun AppTheme(content: @Composable () -> Unit) {
    val nightModeValue by DataStore.nightTheme.collectAsStateWithLifecycle()
    val systemDarkMode = rememberPlatformSystemDarkMode()
    val isDarkMode = remember(nightModeValue, systemDarkMode) {
        when (nightModeValue) {
            1 -> true
            2 -> false
            else -> systemDarkMode
        }
    }
    val appTheme by DataStore.appTheme.collectAsStateWithLifecycle()
    val themedTopBar by DataStore.themedTopBar.collectAsStateWithLifecycle()
    val dynamicScheme = if (appTheme == DYNAMIC) {
        rememberDynamicColorScheme(isDarkMode)
    } else {
        null
    }
    CompositionLocalProvider(
        LocalThemedTopBarEnabled provides (themedTopBar && appTheme != DYNAMIC),
    ) {
        AppTheme(appTheme = appTheme, isDarkMode = isDarkMode, dynamicScheme = dynamicScheme, content = content)
    }
}

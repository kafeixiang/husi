package fr.husi.compose

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarScrollBehavior
import androidx.compose.material3.surfaceColorAtElevation
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.util.fastCoerceIn
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import fr.husi.Key
import fr.husi.compose.theme.DEFAULT
import fr.husi.compose.theme.DYNAMIC
import fr.husi.database.DataStore

/**
 * 全局 TopBar 颜色注入 Local。
 * 用于将 TopBar 的“浮光跃彩”计算色向下传递给 TabRow 等组件。
 */
val LocalHusiTopBarColor = staticCompositionLocalOf<Color?> { null }

/**
 * 获取当前的 TopBar 容器颜色。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun husiTopBarColor(scrollBehavior: TopAppBarScrollBehavior?): Color {
    return LocalHusiTopBarColor.current ?: husiComputeTopBarColor(scrollBehavior)
}

/**
 * 集中处理 Husi 的顶部栏背景注入逻辑。
 */
@OptIn(ExperimentalMaterial3Api::class)
fun Modifier.husiTopBarBackground(scrollBehavior: TopAppBarScrollBehavior?): Modifier = composed {
    val color = husiComputeTopBarColor(scrollBehavior)
    background(if (scrollBehavior != null) color else Color.Transparent)
}

/**
 * 底层颜色计算函数，整合 M3 默认逻辑与 Husi “浮光跃彩”逻辑。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun husiComputeTopBarColor(scrollBehavior: TopAppBarScrollBehavior?): Color {
    val isEnabled by DataStore.configurationStore
        .booleanFlow(Key.THEMED_TOP_BAR, false)
        .collectAsStateWithLifecycle(DataStore.themedTopBar)
    val appTheme by DataStore.configurationStore
        .intFlow(Key.APP_THEME, DEFAULT)
        .collectAsStateWithLifecycle(DataStore.appTheme)

    val topAppBarColors = TopAppBarDefaults.topAppBarColors()
    val overlappedFraction = scrollBehavior?.state?.overlappedFraction?.fastCoerceIn(0f, 1f) ?: 0f
    val scrolledTonalColor = MaterialTheme.colorScheme.surfaceColorAtElevation(3.dp)

    val targetValue = if (!isEnabled || appTheme == DYNAMIC) {
        lerp(topAppBarColors.containerColor, topAppBarColors.scrolledContainerColor, overlappedFraction)
    } else {
        lerp(MaterialTheme.colorScheme.primaryContainer, scrolledTonalColor.copy(alpha = 0.7f), overlappedFraction)
    }

    return animateColorAsState(
        targetValue = targetValue,
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "husiTopBarColor",
    ).value
}

/**
 * 包装 Composable，自动注入顶部栏颜色 Local。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HusiTopBarColorProvider(
    scrollBehavior: TopAppBarScrollBehavior?,
    content: @Composable () -> Unit,
) {
    val color = husiComputeTopBarColor(scrollBehavior)
    CompositionLocalProvider(LocalHusiTopBarColor provides color) {
        content()
    }
}

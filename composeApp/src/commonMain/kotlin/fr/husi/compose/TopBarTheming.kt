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
import androidx.compose.runtime.getValue
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
 * 集中处理 Husi 的顶部栏背景注入逻辑。
 */
@OptIn(ExperimentalMaterial3Api::class)
fun Modifier.husiTopBarBackground(scrollBehavior: TopAppBarScrollBehavior?): Modifier = composed {
    val isEnabled by DataStore.themedTopBar.collectAsStateWithLifecycle()
    val appTheme by DataStore.appTheme.collectAsStateWithLifecycle()

    // 严格遵循：如果功能关闭或处于动态主题，不添加任何背景修饰符，保持 100% 原生透明滚动效果
    if (!isEnabled || appTheme == DYNAMIC) return@composed this

    background(husiAppBarContainerColor(scrollBehavior))
}

/**
 * 获取插值背景色，供 TabRow 等组件同步使用。
 * 
 * 修复同步与闪白问题：
 * 1. 统一所有页面的颜色计算逻辑。
 * 2. 使用 DataStore 属性作为 collectAsStateWithLifecycle 的初始值，减少初次渲染时的加载闪烁。
 * 3. 当功能关闭时，自动返回 Material 3 标准的插值背景色，确保 100% 视觉一致性。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun husiAppBarContainerColor(scrollBehavior: TopAppBarScrollBehavior?): Color {
    val isEnabled by DataStore.themedTopBar.collectAsStateWithLifecycle()
    val appTheme by DataStore.appTheme.collectAsStateWithLifecycle()

    val topAppBarColors = TopAppBarDefaults.topAppBarColors()
    val isThemed = isEnabled && appTheme != DYNAMIC

    val overlappedFraction = scrollBehavior?.state?.overlappedFraction?.fastCoerceIn(0f, 1f) ?: 0f

    val targetColor = if (isThemed) {
        lerp(
            MaterialTheme.colorScheme.primaryContainer,
            MaterialTheme.colorScheme.surfaceColorAtElevation(3.dp).copy(alpha = 0.7f),
            overlappedFraction
        )
    } else {
        lerp(
            topAppBarColors.containerColor,
            topAppBarColors.scrolledContainerColor,
            overlappedFraction
        )
    }

    return animateColorAsState(
        targetValue = targetColor,
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "appBarContainerColor",
    ).value
}

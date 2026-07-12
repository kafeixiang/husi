package fr.husi.compose

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
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
 *
 * 对应受影响的文件（对应页面对应的 Kotlin 文件路径）：
 * 1.  仪表盘: fr.husi.ui.dashboard.Dashboard.kt
 * 2.  配置列表: fr.husi.ui.configuration.ConfigurationScreen.kt
 * 3.  工具箱: fr.husi.ui.tools.ToolsScreen.kt
 * 4.  分组管理: fr.husi.ui.GroupScreen.kt
 * 5.  路由管理: fr.husi.ui.RouteScreen.kt
 * 6.  日志查看: fr.husi.ui.LogcatScreen.kt
 * 7.  应用列表: fr.husi.ui.AbstractAppList.kt / AppListScreen.kt
 * 8.  节点编辑: fr.husi.ui.profile.ProfileEditorScreen.kt / ConfigSettingScreen.kt
 * 9.  文本配置: fr.husi.ui.profile.ConfigEditScreen.kt
 * 10. 设置详情: fr.husi.ui.RouteSettingsScreen.kt / GroupSettingsScreen.kt
 */
@OptIn(ExperimentalMaterial3Api::class)
fun Modifier.husiTopBarBackground(scrollBehavior: TopAppBarScrollBehavior?): Modifier = composed {
    val isEnabled by DataStore.configurationStore
        .booleanFlow(Key.THEMED_TOP_BAR, false)
        .collectAsStateWithLifecycle(false)
    val appTheme by DataStore.configurationStore
        .intFlow(Key.APP_THEME, DEFAULT)
        .collectAsStateWithLifecycle(DEFAULT)

    // --- 核心修正：完美还原上游 ---
    // 如果功能关闭或处于动态主题，不添加任何背景修饰符，100% 保持上游原生外观（包括原生的透明滚动效果）
    if (!isEnabled || appTheme == DYNAMIC) return@composed this

    // --- 开启“浮光跃彩”：实现华丽玻璃感 ---
    val scrolledTonalColor = MaterialTheme.colorScheme.surfaceColorAtElevation(3.dp)
    val animatedColor by animateColorAsState(
        targetValue = lerp(
            MaterialTheme.colorScheme.primaryContainer,
            // 滚动后：使用 0.5f 透明度，确保能清晰看到下方文字，营造高级的透明 Surface 感
            scrolledTonalColor.copy(alpha = 0.7f),
            scrollBehavior?.state?.overlappedFraction?.fastCoerceIn(0f, 1f) ?: 0f,
        ),
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "appBarContainerColor",
    )
    background(animatedColor)
}

/**
 * 获取插值背景色，供 TabRow 等组件同步使用。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun husiAppBarContainerColor(scrollBehavior: TopAppBarScrollBehavior?): Color {
    val isEnabled by DataStore.configurationStore
        .booleanFlow(Key.THEMED_TOP_BAR, false)
        .collectAsStateWithLifecycle(false)
    val appTheme by DataStore.configurationStore
        .intFlow(Key.APP_THEME, DEFAULT)
        .collectAsStateWithLifecycle(DEFAULT)

    if (!isEnabled || appTheme == DYNAMIC) return Color.Transparent

    val scrolledTonalColor = MaterialTheme.colorScheme.surfaceColorAtElevation(3.dp)
    return animateColorAsState(
        targetValue = lerp(
            MaterialTheme.colorScheme.primaryContainer,
            scrolledTonalColor.copy(alpha = 0.7f),
            scrollBehavior?.state?.overlappedFraction?.fastCoerceIn(0f, 1f) ?: 0f,
        ),
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "appBarContainerColor",
    ).value
}

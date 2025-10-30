package io.nekohasekai.sagernet.ui.tools

import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.vectorResource
import android.os.Bundle
import android.view.View
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.ui.res.stringResource
import androidx.core.view.GravityCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.fragment.app.Fragment
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.google.android.material.tabs.TabLayoutMediator
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.compose.SimpleIconButton
import io.nekohasekai.sagernet.compose.theme.AppTheme
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.databinding.LayoutToolsBinding
import io.nekohasekai.sagernet.ktx.isExpert
import io.nekohasekai.sagernet.ui.MainActivity
import io.nekohasekai.sagernet.ui.OnKeyDownFragment
import io.nekohasekai.sagernet.utils.Theme

@OptIn(ExperimentalMaterial3Api::class)
class ToolsFragment : OnKeyDownFragment(R.layout.layout_tools) {

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val tools = mutableListOf<NamedFragment>()
        tools.add(NetworkFragment())
        tools.add(BackupFragment())
        if (isExpert) tools.add(DebugFragment())

        val binding = LayoutToolsBinding.bind(view)
        binding.toolbar.setContent {
            @Suppress("DEPRECATION")
            AppTheme {
                TopAppBar(
                    title = { Text(stringResource(R.string.menu_tools)) },
                    navigationIcon = {
                        SimpleIconButton(
                            imageVector = ImageVector.vectorResource(R.drawable.menu),
                            contentDescription = stringResource(R.string.menu),
                        ) {
                            (requireActivity() as MainActivity).binding
                                .drawerLayout.openDrawer(GravityCompat.START)
                        }
                    },
                    colors = if (DataStore.appTheme == Theme.BLACK || DataStore.appTheme == Theme.DYNAMIC) TopAppBarDefaults.topAppBarColors() else TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                        titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                        navigationIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                        actionIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                )
            }
        }
        binding.toolsPager.adapter = ToolsAdapter(tools)

        ViewCompat.setOnApplyWindowInsetsListener(binding.toolsTab) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            v.updatePadding(
                left = bars.left,
                right = bars.right,
            )
            insets
        }
        ViewCompat.setOnApplyWindowInsetsListener(binding.toolsPager) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            v.updatePadding(
                left = bars.left,
                right = bars.right,
            )
            insets
        }

        TabLayoutMediator(binding.toolsTab, binding.toolsPager) { tab, position ->
            tab.text = tools[position].getName(requireContext())
            tab.view.setOnLongClickListener { // clear toast
                true
            }
        }.attach()
    }

    inner class ToolsAdapter(val tools: List<Fragment>) : FragmentStateAdapter(this) {

        override fun getItemCount() = tools.size

        override fun createFragment(position: Int) = tools[position]
    }

}

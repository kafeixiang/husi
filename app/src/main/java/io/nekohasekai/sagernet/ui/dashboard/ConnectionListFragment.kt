package io.nekohasekai.sagernet.ui.dashboard

import android.os.Bundle
import android.text.format.Formatter
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isVisible
import androidx.core.view.updatePadding
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.common.hash.Hashing
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.aidl.Connection
import io.nekohasekai.sagernet.databinding.LayoutDashboardListBinding
import io.nekohasekai.sagernet.databinding.ViewConnectionItemBinding
import io.nekohasekai.sagernet.ktx.dp2px
import io.nekohasekai.sagernet.ui.MainActivity
import kotlinx.coroutines.launch
import java.nio.charset.StandardCharsets

class ConnectionListFragment : Fragment(R.layout.layout_dashboard_list) {

    private lateinit var binding: LayoutDashboardListBinding
    private val viewModel by viewModels<ConnectionListFragmentViewModel>()
    private val dashboardViewModel by viewModels<DashboardFragmentViewModel>({ requireParentFragment() })
    private lateinit var adapter: ConnectionAdapter

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding = LayoutDashboardListBinding.bind(view)
        ViewCompat.setOnApplyWindowInsetsListener(binding.recycleView) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            v.updatePadding(
                left = bars.left + dp2px(8),
                right = bars.right + dp2px(8),
                bottom = bars.bottom + dp2px(64),
            )
            insets
        }
        binding.recycleView.adapter = ConnectionAdapter().also {
            adapter = it
        }
        ItemTouchHelper(SwipeToDeleteCallback(adapter)).attachToRecyclerView(binding.recycleView)

        lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::handleUiState)
            }
        }

        lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                dashboardViewModel.sortState.collect { sortState ->
                    viewModel.setDescending(sortState.isDescending)
                    viewModel.updateSortMode(sortState.sortMode)
                }
            }
        }
        lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                dashboardViewModel.searchQuery.collect { query ->
                    viewModel.query = query
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()

        viewModel.initialize((requireActivity() as MainActivity).connection.service!!)
    }

    private suspend fun handleUiState(state: ConnectionListFragmentUiState) {
        if (state.connections.isEmpty()) {
            binding.connectionNotFound.isVisible = true
            binding.recycleView.isVisible = false
            adapter.submitList(emptyList())
            return
        }

        binding.connectionNotFound.isVisible = false
        binding.recycleView.isVisible = true
        adapter.submitList(state.connections)
    }

    override fun onPause() {
        viewModel.stop()
        super.onPause()
    }

    private inner class ConnectionAdapter :
        ListAdapter<Connection, Holder>(connectionDiffCallback) {
        init {
            setHasStableIds(true)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
            return Holder(
                ViewConnectionItemBinding.inflate(
                    LayoutInflater.from(parent.context),
                    parent,
                    false,
                )
            )
        }

        override fun onBindViewHolder(holder: Holder, position: Int) {
            holder.bind(getItem(position))
        }

        override fun getItemId(position: Int): Long {
            return getItem(position).uuid.murmurHash()
        }

        private fun String.murmurHash(): Long {
            return Hashing.murmur3_128().hashString(this, StandardCharsets.UTF_8).asLong()
        }

    }

    private val connectionDiffCallback = object : DiffUtil.ItemCallback<Connection>() {
        override fun areItemsTheSame(old: Connection, new: Connection): Boolean {
            return old.uuid == new.uuid
        }

        override fun areContentsTheSame(old: Connection, new: Connection): Boolean {
            return old == new
        }
    }

    private inner class Holder(
        private val binding: ViewConnectionItemBinding,
    ) : RecyclerView.ViewHolder(binding.root) {
        fun bind(connection: Connection) {
            var networkText = connection.network.uppercase()
            connection.protocol?.let { networkText += "/" + it.uppercase() }
            binding.connectionNetwork.text = networkText
            binding.connectionInbound.text = connection.inbound
            binding.connectionDestination.text = connection.dst
            binding.connectionHost.let {
                it.isVisible = if (
                    connection.host.isNotBlank() &&
                    // If use domain to connect, not show host.
                    !connection.dst.startsWith(connection.host)
                ) {
                    it.text = connection.host
                    true
                } else {
                    false
                }
            }
            binding.connectionTraffic.text = binding.connectionTraffic.context.getString(
                R.string.traffic,
                Formatter.formatFileSize(
                    binding.connectionTraffic.context,
                    connection.uploadTotal,
                ),
                Formatter.formatFileSize(
                    binding.connectionTraffic.context,
                    connection.downloadTotal,
                ),
            )
            binding.connectionChain.text = connection.chain
            binding.root.setOnClickListener {
                (requireActivity() as MainActivity)
                    .supportFragmentManager
                    .beginTransaction()
                    .replace(R.id.fragment_holder, ConnectionFragment(connection))
                    .addToBackStack(null)
                    .commit()
            }
        }
    }

    private inner class SwipeToDeleteCallback(private val adapter: ConnectionAdapter) :
        ItemTouchHelper.Callback() {
        override fun getMovementFlags(
            recyclerView: RecyclerView,
            viewHolder: RecyclerView.ViewHolder,
        ): Int {
            val swipeFlags = ItemTouchHelper.LEFT
            return makeMovementFlags(0, swipeFlags)
        }

        override fun onMove(
            recyclerView: RecyclerView,
            viewHolder: RecyclerView.ViewHolder,
            target: RecyclerView.ViewHolder,
        ): Boolean {
            // No move action
            return false
        }

        override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
            lifecycleScope.launch {
                (requireActivity() as MainActivity)
                    .connection
                    .service
                    ?.closeConnection(adapter.currentList[viewHolder.absoluteAdapterPosition].uuid)
            }
        }
    }

    fun connectionSize(): Int {
        return adapter.currentList.size
    }
}

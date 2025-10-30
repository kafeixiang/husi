package io.nekohasekai.sagernet.widget

import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.ui.StringOrRes

class UndoSnackbarManager<in T>(
    private val snackbar: SnackbarAdapter,
    private val callback: Interface<T>,
) {

    /**
     * @param undo Callback for undoing removals.
     * @param commit Callback for committing removals.
     */
    interface Interface<in T> {
        fun undo(actions: List<Pair<Int, T>>)
        fun commit(actions: List<Pair<Int, T>>)
    }

    /**
     * Adapt compose and view.
     */
    interface SnackbarAdapter {
        fun setMessage(message: StringOrRes): SnackbarAdapter
        fun setAction(actionLabel: StringOrRes): SnackbarAdapter
        fun setOnAction(block: () -> Unit): SnackbarAdapter
        fun setOnDismiss(block: () -> Unit): SnackbarAdapter

         fun show()

        fun flush()
    }

    private val recycleBin = ArrayList<Pair<Int, T>>()

    fun remove(items: Collection<Pair<Int, T>>) {
        recycleBin.addAll(items)
        val count = recycleBin.size
        snackbar.flush()
        snackbar.setMessage(StringOrRes.PluralsRes(R.plurals.removed, count, count))
            .setAction(StringOrRes.Res(R.string.undo))
            .setOnAction {
                callback.undo(recycleBin.reversed())
                recycleBin.clear()
            }
            .setOnDismiss {
                callback.commit(recycleBin.toList())
                recycleBin.clear()
            }
            .show()
    }

    fun remove(vararg items: Pair<Int, T>) = remove(items.toList())

    fun flush() = snackbar.flush()
}

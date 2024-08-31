package io.nekohasekai.sagernet.ui.tools

import android.content.ClipData
import android.os.Bundle
import androidx.appcompat.app.AlertDialog
import androidx.core.view.isVisible
import com.google.android.material.snackbar.Snackbar
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.databinding.LayoutGetCertBinding
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import io.nekohasekai.sagernet.ui.ThemedActivity
import libcore.Libcore

class GetCertActivity : ThemedActivity() {

    private lateinit var binding: LayoutGetCertBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = LayoutGetCertBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(findViewById(R.id.toolbar))
        supportActionBar?.apply {
            setTitle(R.string.get_cert)
            setDisplayHomeAsUpEnabled(true)
            setHomeAsUpIndicator(R.drawable.baseline_arrow_back_24)
        }

        binding.getCert.setOnClickListener {
            SagerNet.inputMethod.hideSoftInputFromWindow(binding.root.windowToken, 0)
            copyCert()
        }
    }


    private fun copyCert() {
        binding.waitLayout.isVisible = true

        val server = binding.pinCertServer.text.toString()
        val serverName = binding.pinCertServerName.text.toString()
        val protocol = binding.pinCertProtocol.selectedItemPosition

        runOnDefaultDispatcher {
            try {
                val certificate = Libcore.getCert(server, serverName, protocol)
                Logs.i(certificate)

                val clipData = ClipData.newPlainText("Certificate", certificate)
                SagerNet.clipboard.setPrimaryClip(clipData)

                Snackbar.make(
                    binding.root,
                    R.string.get_cert_success,
                    Snackbar.LENGTH_SHORT
                ).show()

                onMainDispatcher {
                    binding.waitLayout.isVisible = false
                }
            } catch (e: Exception) {
                Logs.w(e)
                onMainDispatcher {
                    binding.waitLayout.isVisible = false
                    AlertDialog.Builder(this@GetCertActivity)
                        .setTitle(R.string.error_title)
                        .setMessage(e.toString())
                        .setPositiveButton(android.R.string.ok) { _, _ -> }
                        .runCatching { show() }
                }
            }
        }
    }

}

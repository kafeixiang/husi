package fr.husi.fmt.ssr

import kotlinx.serialization.Serializable as KxsSerializable
import com.esotericsoftware.kryo.io.ByteBufferInput
import com.esotericsoftware.kryo.io.ByteBufferOutput
import fr.husi.fmt.AbstractBean
import fr.husi.fmt.KryoConverters

@KxsSerializable
class ShadowsocksRBean : AbstractBean() {

    companion object {
        @JvmField
        val CREATOR = object : CREATOR<ShadowsocksRBean>() {
            override fun newInstance(): ShadowsocksRBean {
                return ShadowsocksRBean()
            }

            override fun newArray(size: Int): Array<ShadowsocksRBean?> {
                return arrayOfNulls(size)
            }
        }
    }

    var password = ""
    var method = "aes-256-cfb"
    var protocol = "origin"
    var protocolParam = ""
    var obfs = "plain"
    var obfsParam = ""
    var network = "tcp"

    override fun initializeDefaultValues() {
        super.initializeDefaultValues()
        if (method.isBlank()) method = "aes-256-cfb"
        if (protocol.isBlank()) protocol = "origin"
        if (obfs.isBlank()) obfs = "plain"
        if (network.isBlank()) network = "tcp"
    }

    override fun serialize(output: ByteBufferOutput) {
        output.writeInt(2)
        super.serialize(output)
        output.writeString(password)
        output.writeString(method)
        output.writeString(protocol)
        output.writeString(protocolParam)
        output.writeString(obfs)
        output.writeString(obfsParam)
        output.writeString(network)
    }

    override fun deserialize(input: ByteBufferInput) {
        val version = input.readInt()
        super.deserialize(input)
        password = input.readString() ?: ""
        method = input.readString() ?: "aes-256-cfb"
        protocol = input.readString() ?: "origin"
        protocolParam = input.readString() ?: ""
        obfs = input.readString() ?: "plain"
        obfsParam = input.readString() ?: ""
        
        if (version >= 2) {
            network = input.readString() ?: "tcp"
        }

        if (version == 0) {
            if (obfs == "tls_simple") {
                obfs = "plain"
            }
            if (obfs == "tls1.2_ticket_fastauth") {
                obfs = "tls1.2_ticket_auth"
            }
        }
    }

    override fun clone(): ShadowsocksRBean {
        return KryoConverters.deserialize(ShadowsocksRBean(), KryoConverters.serialize(this))
    }

    override val defaultPort get() = 8388
}

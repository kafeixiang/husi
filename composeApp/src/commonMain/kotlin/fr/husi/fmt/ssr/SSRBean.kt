package fr.husi.fmt.ssr

import kotlinx.serialization.Serializable as KxsSerializable
import com.esotericsoftware.kryo.io.ByteBufferInput
import com.esotericsoftware.kryo.io.ByteBufferOutput
import fr.husi.fmt.AbstractBean
import fr.husi.fmt.KryoConverters

@KxsSerializable
class SSRBean : AbstractBean() {

    companion object {
        @JvmField
        val CREATOR = object : CREATOR<SSRBean>() {
            override fun newInstance(): SSRBean {
                return SSRBean()
            }

            override fun newArray(size: Int): Array<SSRBean?> {
                return arrayOfNulls(size)
            }
        }
    }

    var method: String = "aes-256-cfb"
    var password: String = ""
    var protocol: String = "origin"
    var protocolParam: String = ""
    var obfs: String = "plain"
    var obfsParam: String = ""
    var group: String = ""
    var udpOverTcp: Boolean = false

    override fun initializeDefaultValues() {
        super.initializeDefaultValues()
        if (method.isBlank()) method = "aes-256-cfb"
        if (protocol.isBlank()) protocol = "origin"
        if (obfs.isBlank()) obfs = "plain"
    }

    override fun serialize(output: ByteBufferOutput) {
        output.writeInt(2)
        super.serialize(output)
        output.writeString(method)
        output.writeString(password)
        output.writeString(protocol)
        output.writeString(protocolParam)
        output.writeString(obfs)
        output.writeString(obfsParam)
        output.writeString(group)
        output.writeBoolean(udpOverTcp)
    }

    override fun deserialize(input: ByteBufferInput) {
        val version = input.readInt()
        super.deserialize(input)
        method = input.readString()
        password = input.readString()
        protocol = input.readString()
        protocolParam = input.readString()
        obfs = input.readString()
        obfsParam = input.readString()
        if (version >= 2) {
            group = input.readString()
            udpOverTcp = input.readBoolean()
        }
    }

    override fun applyFeatureSettings(other: AbstractBean) {
        if (other !is SSRBean) return
    }

    override fun clone(): SSRBean {
        return KryoConverters.deserialize(SSRBean(), KryoConverters.serialize(this))
    }

    override val defaultPort get() = 8388
}

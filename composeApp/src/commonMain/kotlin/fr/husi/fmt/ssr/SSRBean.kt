package fr.husi.fmt.ssr

import kotlinx.serialization.Serializable as KxsSerializable
import fr.husi.fmt.AbstractBean
import fr.husi.fmt.BeanConverters
import fr.husi.io.BinaryInput
import fr.husi.io.BinaryOutput

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

    override fun initializeDefaultValues() {
        super.initializeDefaultValues()
        if (method.isBlank()) method = "aes-256-cfb"
        if (protocol.isBlank()) protocol = "origin"
        if (obfs.isBlank()) obfs = "plain"
    }

    override fun serialize(output: BinaryOutput) {
        output.writeInt(1)
        super.serialize(output)
        output.writeString(method)
        output.writeString(password)
        output.writeString(protocol)
        output.writeString(protocolParam)
        output.writeString(obfs)
        output.writeString(obfsParam)
    }

    override fun deserialize(input: BinaryInput) {
        val version = input.readInt()
        super.deserialize(input)
        method = input.readString()
        password = input.readString()
        protocol = input.readString()
        protocolParam = input.readString()
        obfs = input.readString()
        obfsParam = input.readString()
    }

    override fun applyFeatureSettings(other: AbstractBean) {
        if (other !is SSRBean) return
    }

    override fun clone(): SSRBean {
        return BeanConverters.ssrDeserialize(BeanConverters.serialize(this))!!
    }

    override val defaultPort get() = 8388
}

package fr.husi.fmt.trojan_go

import fr.husi.fmt.AbstractBean
import fr.husi.fmt.BeanConverters
import fr.husi.fmt.ValidateResult
import fr.husi.io.BinaryInput
import fr.husi.io.BinaryOutput
import fr.husi.resources.Res
import fr.husi.resources.warn_insecure
import kotlinx.serialization.Serializable as KxsSerializable

@KxsSerializable
class TrojanGoBean : AbstractBean() {

    companion object {
        @JvmField
        val CREATOR = object : CREATOR<TrojanGoBean>() {
            override fun newInstance(): TrojanGoBean = TrojanGoBean()
            override fun newArray(size: Int): Array<TrojanGoBean?> = arrayOfNulls(size)
        }
    }

    var password: String = ""
    var sni: String = ""
    var type: String = "original"
    var host: String = ""
    var path: String = ""
    var encryption: String = "none"
    var ssMethod: String = "aes-128-gcm"
    var ssPassword: String = ""
    var plugin: String = ""
    var mux: Boolean = false
    var muxConcurrency: Int = 8
    var allowInsecure: Boolean = false
    var udp: Boolean = true

    override fun network(): String = if (udp) "tcp,udp" else "tcp"

    override fun initializeDefaultValues() {
        super.initializeDefaultValues()
        if (type.isBlank()) type = "original"
        if (encryption.isBlank()) encryption = "none"
        if (ssMethod.isBlank()) ssMethod = "aes-128-gcm"
        if (muxConcurrency <= 0) muxConcurrency = 8
    }

    override fun isInsecure(): ValidateResult {
        val result = super.isInsecure()
        if (shouldReturnFromInsecureCheck(result)) return result
        if (allowInsecure) {
            return ValidateResult.Insecure(Res.string.warn_insecure)
        }
        return ValidateResult.Secure.Continue
    }

    override fun serialize(output: BinaryOutput) {
        output.writeInt(2)
        super.serialize(output)
        output.writeString(password)
        output.writeString(sni)
        output.writeString(type)
        output.writeString(host)
        output.writeString(path)
        output.writeString(encryption)
        output.writeString(ssMethod)
        output.writeString(ssPassword)
        output.writeBoolean(mux)
        output.writeInt(muxConcurrency)
        output.writeBoolean(allowInsecure)
        output.writeBoolean(udp)
        output.writeString(plugin)
    }

    override fun deserialize(input: BinaryInput) {
        val version = input.readInt()
        super.deserialize(input)
        password = input.readString()
        sni = input.readString()
        type = input.readString()
        host = input.readString()
        path = input.readString()
        encryption = input.readString()
        ssMethod = input.readString()
        ssPassword = input.readString()
        mux = input.readBoolean()
        muxConcurrency = input.readInt()
        allowInsecure = input.readBoolean()
        udp = input.readBoolean()
        if (version >= 2) {
            plugin = input.readString()
        }
    }

    override fun applyFeatureSettings(other: AbstractBean) {
        if (other !is TrojanGoBean) return
        other.allowInsecure = allowInsecure
        other.mux = mux
        other.udp = udp
        other.plugin = plugin
    }

    override fun clone(): TrojanGoBean {
        return BeanConverters.trojanGoDeserialize(BeanConverters.serialize(this))!!
    }

    override val defaultPort get() = 443
}

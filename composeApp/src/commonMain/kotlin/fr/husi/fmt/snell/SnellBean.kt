package fr.husi.fmt.snell

import kotlinx.serialization.Serializable as KxsSerializable
import com.esotericsoftware.kryo.io.ByteBufferInput
import com.esotericsoftware.kryo.io.ByteBufferOutput
import fr.husi.fmt.AbstractBean
import fr.husi.fmt.KryoConverters
import fr.husi.fmt.ValidateResult
import fr.husi.resources.*

@KxsSerializable
class SnellBean : AbstractBean() {

    companion object {
        @JvmField
        val CREATOR = object : CREATOR<SnellBean>() {
            override fun newInstance(): SnellBean {
                return SnellBean()
            }

            override fun newArray(size: Int): Array<SnellBean?> {
                return arrayOfNulls(size)
            }
        }
    }

    var psk: String = ""
    var version: Int = 4
    var udp: Boolean = true
    var reuse: Boolean = false
    var obfsType: String = "none" // none, http
    var obfsHost: String = ""
    var tls: Boolean = false
    var sni: String = ""
    var allowInsecure: Boolean = false
    var udpOverTcp: Boolean = false

    fun canObfs(): Boolean = version < 5
    fun canTls(): Boolean = version < 5
    fun canUoT(): Boolean = version < 5
    fun canReuse(): Boolean = version >= 4
    fun canMux(): Boolean = version < 4

    override fun initializeDefaultValues() {
        super.initializeDefaultValues()
        if (version == 0) version = 4
        if (obfsType.isBlank()) obfsType = "none"
    }

    override fun serialize(output: ByteBufferOutput) {
        output.writeInt(5) // Bean Version 5
        super.serialize(output)
        output.writeString(psk)
        output.writeInt(version)
        output.writeString(obfsType)
        output.writeString(obfsHost)
        output.writeBoolean(udp)
        output.writeBoolean(tls)
        output.writeString(sni)
        output.writeBoolean(allowInsecure)
        output.writeBoolean(reuse)
        output.writeBoolean(udpOverTcp)
        
        // Mux settings from AbstractBean
        output.writeBoolean(serverMux)
        output.writeInt(serverMuxType)
        output.writeInt(serverMuxNumber)
        output.writeBoolean(serverMuxPadding)
        output.writeInt(serverMuxStrategy)
    }

    override fun deserialize(input: ByteBufferInput) {
        val beanVersion = input.readInt()
        super.deserialize(input)
        psk = input.readString()
        this.version = input.readInt()
        obfsType = input.readString()
        obfsHost = input.readString()
        if (beanVersion >= 2) {
            udp = input.readBoolean()
        }
        if (beanVersion >= 3) {
            tls = input.readBoolean()
            sni = input.readString()
            allowInsecure = input.readBoolean()
        }
        if (beanVersion >= 4) {
            reuse = input.readBoolean()
            udpOverTcp = input.readBoolean()
        }
        if (beanVersion >= 5) {
            serverMux = input.readBoolean()
            serverMuxType = input.readInt()
            serverMuxNumber = input.readInt()
            serverMuxPadding = input.readBoolean()
            serverMuxStrategy = input.readInt()
        }
    }

    override fun network(): String {
        return if (udp) "tcp,udp" else "tcp"
    }

    override fun isInsecure(): ValidateResult {
        val result = super.isInsecure()
        if (shouldReturnFromInsecureCheck(result)) return result
        if (version < 3) {
            return ValidateResult.Insecure(Res.string.warn_insecure)
        }
        return ValidateResult.Secure.Continue
    }

    override fun clone(): SnellBean {
        return KryoConverters.deserialize(SnellBean(), KryoConverters.serialize(this))
    }

    override val defaultPort get() = 443
}

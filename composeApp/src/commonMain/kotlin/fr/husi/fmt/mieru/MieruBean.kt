package fr.husi.fmt.mieru

import kotlinx.serialization.Serializable as KxsSerializable
import com.esotericsoftware.kryo.io.ByteBufferInput
import com.esotericsoftware.kryo.io.ByteBufferOutput
import fr.husi.fmt.AbstractBean
import fr.husi.fmt.KryoConverters

@KxsSerializable
class MieruBean : AbstractBean() {

    companion object {
        const val PROTOCOL_TCP = "TCP"
        const val PROTOCOL_UDP = "UDP"

        @JvmField
        val CREATOR = object : CREATOR<MieruBean>() {
            override fun newInstance(): MieruBean {
                return MieruBean()
            }

            override fun newArray(size: Int): Array<MieruBean?> {
                return arrayOfNulls(size)
            }
        }
    }

    var protocol: String = PROTOCOL_TCP
    var username: String = ""
    var password: String = ""
    var mtu: Int = 1400
    var trafficPattern: String = ""
    var handshakeMode: Int = 2 // 0: DEFAULT, 1: STANDARD, 2: NO_WAIT
    var userHint: Boolean = false
    var serverPorts: String = ""

    override fun initializeDefaultValues() {
        super.initializeDefaultValues()
        if (protocol.isEmpty()) protocol = PROTOCOL_TCP
        // Mieru multiplexing level is 0-4
        if (serverMuxNumber !in 0..4) serverMuxNumber = 0
    }

    override fun serialize(output: ByteBufferOutput) {
        output.writeInt(5) // Version 5: Added serverPorts
        super.serialize(output)
        output.writeString(protocol)
        output.writeString(username)
        output.writeString(password)
        if (protocol == PROTOCOL_UDP) {
            output.writeInt(mtu)
        }
        output.writeString(trafficPattern)
        output.writeInt(handshakeMode)
        output.writeBoolean(userHint)
        output.writeString(serverPorts)
    }

    override fun deserialize(input: ByteBufferInput) {
        val version = input.readInt()
        super.deserialize(input)
        protocol = input.readString().uppercase()
        username = input.readString()
        password = input.readString()
        if (version == 1) {
            if (protocol == PROTOCOL_UDP) {
                mtu = input.readInt()
            }
        } else if (version >= 2) {
            if (protocol == PROTOCOL_UDP) {
                mtu = input.readInt()
            }
            trafficPattern = input.readString()
        }
        if (version >= 3) {
            handshakeMode = input.readInt()
        }
        if (version >= 4) {
            userHint = input.readBoolean()
        }
        if (version >= 5) {
            serverPorts = input.readString()
        }
    }

    override fun applyFeatureSettings(other: AbstractBean) {
        if (other !is MieruBean) return
        protocol = other.protocol
        username = other.username
        password = other.password
        mtu = other.mtu
        trafficPattern = other.trafficPattern
        handshakeMode = other.handshakeMode
        userHint = other.userHint
        serverPorts = other.serverPorts
    }

    override val canTCPing get() = protocol == PROTOCOL_TCP

    override fun clone(): MieruBean {
        return KryoConverters.deserialize(MieruBean(), KryoConverters.serialize(this))
    }
}

package fr.husi.fmt.mieru

import kotlinx.serialization.Serializable as KxsSerializable
import fr.husi.fmt.AbstractBean
import fr.husi.fmt.BeanConverters
import fr.husi.io.BinaryInput
import fr.husi.io.BinaryOutput

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
    var heartbeatInterval: Int = 0
    var heartbeatJitter: Double = 0.0
    var userHint: String = ""

    override fun initializeDefaultValues() {
        super.initializeDefaultValues()
        if (protocol.isEmpty()) protocol = PROTOCOL_TCP
        // Mieru multiplexing level is 0-3
        if (serverMuxNumber !in 0..3) serverMuxNumber = 0
    }

    override fun serialize(output: BinaryOutput) {
        output.writeInt(4) // Version 4: Added heartbeat and userHint
        super.serialize(output)
        output.writeString(protocol)
        output.writeString(username)
        output.writeString(password)
        if (protocol == PROTOCOL_UDP) {
            output.writeInt(mtu)
        }
        output.writeString(trafficPattern)
        output.writeInt(handshakeMode)
        output.writeInt(heartbeatInterval)
        output.writeDouble(heartbeatJitter)
        output.writeString(userHint)
    }

    override fun deserialize(input: BinaryInput) {
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
            heartbeatInterval = input.readInt()
            heartbeatJitter = input.readDouble()
            userHint = input.readString()
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
        heartbeatInterval = other.heartbeatInterval
        heartbeatJitter = other.heartbeatJitter
        userHint = other.userHint
    }

    override val canTCPing get() = protocol == PROTOCOL_TCP

    override fun clone(): MieruBean {
        return BeanConverters.deserialize(MieruBean(), BeanConverters.serialize(this))
    }
}

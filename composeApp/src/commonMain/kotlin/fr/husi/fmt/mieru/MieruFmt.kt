package fr.husi.fmt.mieru

import fr.husi.fmt.SingBoxOptions
import fr.husi.fmt.parseBoxOutbound
import fr.husi.ktx.JSONMap
import fr.husi.ktx.blankAsNull
import fr.husi.ktx.isIpAddress
import fr.husi.ktx.kxs
import fr.husi.ktx.listByLineOrComma
import fr.husi.ktx.queryParameterNotBlank
import fr.husi.ktx.toJsonStringKxs
import fr.husi.libcore.Libcore
import fr.husi.logLevelString
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

fun MieruBean.buildMieruConfig(port: Int, logLevel: Int): String {
    if (password.isEmpty()) error("mieru password is empty")
    val activeProfileName = name.ifBlank { "default" }
    val profile = buildJsonObject {
        put("profileName", activeProfileName)
        putJsonObject("user") {
            put("name", username)
            put("password", password)
        }
        putJsonArray("servers") {
            addJsonObject {
                putJsonArray("portBindings") {
                    if (serverPorts.isNotBlank()) {
                        for (p in serverPorts.listByLineOrComma()) {
                            val portNum = p.toIntOrNull()
                            addJsonObject {
                                if (portNum != null) {
                                    put("port", portNum)
                                } else {
                                    put("portRange", p)
                                }
                                put("protocol", protocol.uppercase())
                            }
                        }
                    } else {
                        addJsonObject {
                            put("port", finalPort)
                            put("protocol", protocol.uppercase())
                        }
                    }
                }
                // mieru refuses to parse a domain name in the ipAddress field.
                if (finalAddress.isIpAddress()) {
                    put("ipAddress", finalAddress)
                } else {
                    put("domainName", finalAddress)
                }
            }
        }
        if (mtu > 0) {
            put("mtu", mtu)
        }
        mieruMuxToString(serverMuxNumber)?.let { level ->
            putJsonObject("multiplexing") { put("level", level) }
        }
        mieruHandshakeToString(handshakeMode)?.let { hsStr ->
            put("handshakeMode", hsStr)
        } ?: put("handshakeMode", "HANDSHAKE_STANDARD")
        trafficPattern.blankAsNull()?.let { pattern ->
            put(
                "trafficPattern",
                runCatching {
                    pattern.parseMieruTrafficPattern()
                }.getOrElse { _ ->
                    Libcore.decodeMieruTrafficPattern(pattern).parseMieruTrafficPattern()
                },
            )
        }
    }
    return buildJsonObject {
        put("activeProfile", activeProfileName)
        put("socks5Port", port)
        logLevel.takeIf { it > 0 }?.let {
            put("loggingLevel", logLevelString(it).uppercase())
        }
        putJsonObject("advancedSettings") { put("noCheckUpdate", true) }
        putJsonArray("profiles") { add(profile) }
    }.toJsonStringKxs()
}

private fun String.parseMieruTrafficPattern(): JsonElement {
    val root = kxs.parseToJsonElement(this) as? JsonObject
        ?: error("mieru traffic pattern is not a JSON object")
    return root["trafficPattern"] ?: root
}

fun parseMieru(link: String): MieruBean = MieruBean().apply {
    val uri = Libcore.parseURL(link)
    serverAddress = uri.host
    serverPort = uri.ports.toIntOrNull() ?: 1080
    username = uri.username
    password = uri.password

    val portParam = uri.queryParameterNotBlank("port")
        ?: uri.queryParameterNotBlank("server_ports")
        ?: uri.queryParameterNotBlank("server-ports")
        ?: uri.queryParameterNotBlank("port_range")
        ?: uri.queryParameterNotBlank("port-range")

    if (!portParam.isNullOrBlank()) {
        if (portParam.contains("-") || portParam.contains(",")) {
            serverPorts = portParam
        } else {
            val p = portParam.toIntOrNull()
            if (p != null) {
                if (uri.ports.isBlank() || serverPort == 1080 || serverPort == 0) {
                    serverPort = p
                } else {
                    serverPorts = portParam
                }
            } else {
                serverPorts = portParam
            }
        }
    }

    protocol = uri.queryParameterNotBlank("transport")?.uppercase()
        ?: uri.queryParameterNotBlank("protocol")?.uppercase()
        ?: MieruBean.PROTOCOL_TCP

    serverMuxNumber = uri.queryParameterNotBlank("multiplexing")
        ?.let { parseMieruMux(it) } ?: 0

    handshakeMode = (uri.queryParameterNotBlank("handshake_mode")
        ?: uri.queryParameterNotBlank("handshake-mode"))
        ?.let { parseMieruHandshake(it) } ?: 1

    trafficPattern = uri.queryParameterNotBlank("traffic_pattern")
        ?: uri.queryParameterNotBlank("traffic-pattern")
        ?: ""

    mtu = uri.queryParameterNotBlank("mtu")?.toIntOrNull() ?: 0

    name = if (uri.fragment.isNotBlank()) uri.fragment
        else uri.queryParameterNotBlank("profile")
        ?: ""
}

fun MieruBean.toUri(): String {
    val url = Libcore.newURL("mierus")
    url.host = serverAddress
    if (serverPort != 0 && serverPort != 1080) {
        url.ports = serverPort.toString()
    }
    url.username = username
    url.password = password
    if (name.isNotBlank()) {
        url.addQueryParameter("profile", name)
    }
    if (serverPorts.isNotBlank()) {
        url.addQueryParameter("port", serverPorts)
    }
    url.addQueryParameter("protocol", protocol.uppercase())
    if (serverMuxNumber > 0) {
        url.addQueryParameter("multiplexing", mieruMuxToString(serverMuxNumber))
    }
    if (handshakeMode != 0) {
        url.addQueryParameter("handshake-mode", mieruHandshakeToString(handshakeMode))
    }
    if (mtu > 0) {
        url.addQueryParameter("mtu", mtu.toString())
    }
    trafficPattern.blankAsNull()?.let { pattern ->
        val base64TrafficPattern = if (pattern.startsWith("{")) {
            runCatching<String> {
                Libcore.encodeMieruTrafficPattern(pattern)
            }.getOrNull() ?: pattern
        } else {
            pattern
        }
        url.addQueryParameter("traffic-pattern", base64TrafficPattern)
    }
    return url.string
}

internal fun parseMieruMux(link: String): Int? = when (link.uppercase()) {
    "MULTIPLEXING_OFF", "OFF" -> 0
    "MULTIPLEXING_LOW", "LOW" -> 1
    "MULTIPLEXING_MIDDLE", "MIDDLE", "MULTIPLEXING_MEDIUM", "MEDIUM" -> 2
    "MULTIPLEXING_HIGH", "HIGH" -> 3
    else -> link.toIntOrNull()
}

internal fun mieruMuxToString(level: Int): String? = when (level) {
    0 -> "MULTIPLEXING_OFF"
    1 -> "MULTIPLEXING_LOW"
    2 -> "MULTIPLEXING_MIDDLE"
    3 -> "MULTIPLEXING_HIGH"
    else -> null
}

internal fun parseMieruHandshake(mode: String): Int? = when (mode.uppercase()) {
    "HANDSHAKE_DEFAULT", "DEFAULT" -> 0
    "HANDSHAKE_STANDARD", "STANDARD", "1-RTT" -> 1
    "HANDSHAKE_NO_WAIT", "0-RTT", "NO_WAIT" -> 2
    else -> mode.toIntOrNull()
}

internal fun mieruHandshakeToString(mode: Int): String? = when (mode) {
    0 -> "HANDSHAKE_DEFAULT"
    1 -> "HANDSHAKE_STANDARD"
    2 -> "HANDSHAKE_NO_WAIT"
    else -> null
}

fun buildSingBoxOutboundMieruBean(bean: MieruBean): SingBoxOptions.Outbound_MieruOptions {
    return SingBoxOptions.Outbound_MieruOptions().apply {
        type = SingBoxOptions.TYPE_MIERU
        server = bean.serverAddress
        if (bean.serverPorts.isNotBlank()) {
            server_ports = bean.serverPorts.listByLineOrComma().toMutableList()
        } else {
            server_port = bean.serverPort
        }
        transport = bean.protocol.uppercase()
        username = bean.username
        password = bean.password
        multiplexing = mieruMuxToString(bean.serverMuxNumber)
        handshake_mode = mieruHandshakeToString(bean.handshakeMode)
        traffic_pattern = bean.trafficPattern.takeIf { it.isNotBlank() && it != "1" }
        mtu = bean.mtu.takeIf { it > 0 }
    }
}

fun parseMieruOutbound(json: JSONMap): MieruBean = MieruBean().apply {
    parseBoxOutbound(json) { key, value ->
        when (key) {
            "server_ports", "server-ports", "port_range", "port-range", "port_ranges", "port-ranges" -> {
                serverPorts = (value as? List<*>)?.joinToString(",") ?: value.toString()
            }
            "port" -> {
                val strVal = (value as? List<*>)?.joinToString(",") ?: value.toString()
                if (strVal.contains("-") || strVal.contains(",")) {
                    serverPorts = strVal
                } else {
                    strVal.toIntOrNull()?.let { serverPort = it }
                }
            }
            "transport" -> protocol = value.toString().uppercase()
            "username", "user" -> username = value.toString()
            "password", "pass" -> password = value.toString()
            "multiplexing" -> serverMuxNumber = parseMieruMux(value.toString()) ?: 0
            "handshake_mode", "handshake-mode" -> handshakeMode = parseMieruHandshake(value.toString()) ?: 0
            "traffic_pattern", "traffic-pattern" -> trafficPattern = value.toString()
            "mtu" -> mtu = value.toString().toIntOrNull() ?: 0
        }
    }
}

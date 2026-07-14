package fr.husi.fmt.mieru

import fr.husi.fmt.SingBoxOptions
import fr.husi.fmt.parseBoxOutbound
import fr.husi.ktx.JSONMap
import fr.husi.ktx.blankAsNull
import fr.husi.ktx.isIpAddress
import fr.husi.ktx.queryParameterNotBlank
import fr.husi.ktx.toJsonStringKxs
import fr.husi.ktx.listByLineOrComma
import fr.husi.libcore.Libcore

fun MieruBean.buildMieruConfig(port: Int, logLevel: Int): String {
    val profile = mutableMapOf<String, Any>(
        "name" to "sing-box",
        "user" to mapOf(
            "name" to username,
            "password" to password,
        ),
        "portBindings" to listOf(
            mapOf(
                "port" to port,
                "protocol" to protocol.uppercase(),
            ),
        ),
    )
    val config = mapOf(
        "profiles" to listOf(profile),
        "logging" to mapOf(
            "level" to when (logLevel) {
                0, 1 -> "PANIC"
                2 -> "ERROR"
                3 -> "WARN"
                4 -> "INFO"
                5 -> "DEBUG"
                6 -> "TRACE"
                else -> "INFO"
            },
        ),
        "servers" to listOf(
            mutableMapOf<String, Any?>(
                "portBindings" to listOf(
                    mapOf(
                        "port" to finalPort,
                        "protocol" to protocol.uppercase(),
                    ),
                ),
                "mtu" to mtu,
                "multiplexing" to mieruMuxToString(serverMuxNumber)?.let { mapOf("level" to it) },
                "handshakeMode" to mieruHandshakeToString(handshakeMode),
                "trafficPattern" to trafficPattern.takeIf { it.isNotBlank() && it != "1" },
            ).also {
                // mieru refuses to parse a domain name in the ipAddress field.
                if (finalAddress.isIpAddress()) {
                    it["ipAddress"] = finalAddress
                } else {
                    it["domainName"] = finalAddress
                }
            },
        ),
        "mtu" to mtu,
        "multiplexing" to mieruMuxToString(serverMuxNumber)?.let { mapOf("level" to it) },
        "handshakeMode" to mieruHandshakeToString(handshakeMode),
    )
    trafficPattern.blankAsNull()?.let { pattern ->
        profile["trafficPattern"] = runCatching<String> {
            Libcore.encodeMieruTrafficPattern(pattern)
        }.getOrNull() ?: pattern
    }
    return config.toJsonStringKxs()
}

fun parseMieru(link: String): MieruBean = MieruBean().apply {
    val uri = Libcore.parseURL(link)
    serverAddress = uri.host
    serverPort = uri.ports.toIntOrNull() ?: 0
    serverPorts = uri.queryParameterNotBlank("server_ports") ?: ""
    username = uri.username
    password = uri.password
    protocol = uri.queryParameterNotBlank("transport")?.uppercase() ?: MieruBean.PROTOCOL_TCP
    serverMuxNumber = uri.queryParameterNotBlank("multiplexing")?.let { parseMieruMux(it) } ?: 0
    handshakeMode = uri.queryParameterNotBlank("handshake_mode")?.let { parseMieruHandshake(it) } ?: 2
    heartbeatInterval = uri.queryParameterNotBlank("heartbeat_interval")?.toIntOrNull() ?: 0
    heartbeatJitter = uri.queryParameterNotBlank("heartbeat_jitter")?.toDoubleOrNull() ?: 0.0
    userHint = uri.queryParameterNotBlank("user_hint") ?: ""
    trafficPattern = uri.queryParameterNotBlank("traffic_pattern")?.let { pattern ->
        runCatching<String> {
            Libcore.decodeMieruTrafficPattern(pattern)
        }.getOrNull() ?: pattern
    } ?: ""
    name = uri.fragment
}

fun MieruBean.toUri(): String {
    val url = Libcore.newURL("mierus")
    url.host = serverAddress
    url.ports = serverPort.toString()
    url.username = username
    url.password = password
    if (name.isNotBlank()) url.fragment = name
    if (serverPorts.isNotBlank()) {
        url.addQueryParameter("server_ports", serverPorts)
    }
    url.addQueryParameter("transport", protocol.lowercase())
    if (serverMuxNumber > 0) {
        url.addQueryParameter("multiplexing", mieruMuxToString(serverMuxNumber))
    }
    if (handshakeMode != 0) {
        url.addQueryParameter("handshake_mode", mieruHandshakeToString(handshakeMode))
    }
    if (heartbeatInterval > 0) {
        url.addQueryParameter("heartbeat_interval", heartbeatInterval.toString())
    }
    if (heartbeatJitter > 0.0) {
        url.addQueryParameter("heartbeat_jitter", heartbeatJitter.toString())
    }
    if (userHint.isNotBlank()) {
        url.addQueryParameter("user_hint", userHint)
    }
    trafficPattern.blankAsNull()?.let { pattern ->
        val base64TrafficPattern = runCatching<String> {
            Libcore.encodeMieruTrafficPattern(pattern)
        }.getOrNull() ?: pattern
        url.addQueryParameter("traffic_pattern", base64TrafficPattern)
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
    "HANDSHAKE_STANDARD", "STANDARD" -> 1
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
        heartbeat_interval = bean.heartbeatInterval.takeIf { it > 0 }?.let { "${it}s" }
        heartbeat_jitter = bean.heartbeatJitter.takeIf { it > 0.0 }
        user_hint = bean.userHint.takeIf { it.isNotBlank() }
        traffic_pattern = bean.trafficPattern.takeIf { it.isNotBlank() && it != "1" }
        mtu = bean.mtu.takeIf { it > 0 }
    }
}

fun parseMieruOutbound(json: JSONMap): MieruBean = MieruBean().apply {
    parseBoxOutbound(json) { key, value ->
        when (key) {
            "server_ports" -> serverPorts = (value as? List<*>)?.joinToString(",") ?: value.toString()
            "transport" -> protocol = value.toString().uppercase()
            "username" -> username = value.toString()
            "password" -> password = value.toString()
            "multiplexing" -> serverMuxNumber = parseMieruMux(value.toString()) ?: 0
            "handshake_mode" -> handshakeMode = parseMieruHandshake(value.toString()) ?: 0
            "heartbeat_interval" -> heartbeatInterval = value.toString().removeSuffix("s").toIntOrNull() ?: 0
            "heartbeat_jitter" -> heartbeatJitter = value.toString().toDoubleOrNull() ?: 0.0
            "user_hint" -> userHint = value.toString()
            "traffic_pattern" -> trafficPattern = value.toString()
            "mtu" -> mtu = value.toString().toIntOrNull() ?: 0
        }
    }
}

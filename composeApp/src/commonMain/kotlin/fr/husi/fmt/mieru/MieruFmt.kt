/******************************************************************************
 * Copyright (C) 2022 by nekohasekai <contact-git@sekai.icu>                  *
 *                                                                            *
 * This program is free software: you can redistribute it and/or modify       *
 * it under the terms of the GNU General Public License as published by       *
 * the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                       *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU General Public License          *
 * along with this program. If not, see <http://www.gnu.org/licenses/>.       *
 *                                                                            *
 ******************************************************************************/

package fr.husi.fmt.mieru

import fr.husi.fmt.SingBoxOptions
import fr.husi.fmt.parseBoxOutbound
import fr.husi.ktx.JSONMap
import fr.husi.ktx.blankAsNull
import fr.husi.ktx.parseBoolean
import fr.husi.ktx.queryParameterNotBlank
import fr.husi.ktx.toJsonMapKxs
import fr.husi.ktx.toJsonStringKxs
import fr.husi.libcore.Libcore
import fr.husi.logLevelString

fun MieruBean.buildMieruConfig(port: Int, logLevel: Int): String {
    val portBindings = if (serverPorts.isNotBlank()) {
        serverPorts.split(",").map { p ->
            val range = p.trim()
            if (range.contains("-")) {
                mapOf(
                    "portRange" to range,
                    "protocol" to protocol.uppercase(),
                )
            } else {
                mapOf(
                    "port" to (range.toIntOrNull() ?: finalPort),
                    "protocol" to protocol.uppercase(),
                )
            }
        }
    } else {
        listOf(
            mapOf(
                "port" to finalPort,
                "protocol" to protocol.uppercase(),
            ),
        )
    }
    val basic = mutableMapOf(
        "activeProfile" to "default",
        "socks5Port" to port,
        "loggingLevel" to logLevel.takeIf { it > 0 }?.let { logLevelString(it).uppercase() },
        "advancedSettings" to mapOf("noCheckUpdate" to true),
        "profiles" to listOf(
            mutableMapOf(
                "profileName" to "default",
                "user" to mapOf(
                    "name" to username,
                    "password" to password.also {
                        if (it.isEmpty()) error("mieru password is empty")
                    },
                ),
                "servers" to listOf(
                    mapOf(
                        "ipAddress" to finalAddress,
                        "portBindings" to portBindings,
                    ),
                ),
                "mtu" to mtu,
                "multiplexing" to mieruMuxToString(serverMuxNumber)?.let { mapOf("level" to it) },
                "handshakeMode" to mieruHandshakeToString(handshakeMode),
                "userHint" to userHint,
                "trafficPattern" to trafficPattern.takeIf { it.isNotBlank() && it != "1" },
            ),
        ),
    )
    trafficPattern.blankAsNull()?.let { trafficPattern ->
        basic["trafficPattern"] = runCatching {
            trafficPattern.toJsonMapKxs().let {
                it["trafficPattern"] ?: it
            }
        }.getOrElse { _ ->
            Libcore.decodeMieruTrafficPattern(trafficPattern).toJsonMapKxs().let {
                it["trafficPattern"] ?: it
            }
        }
    }
    return basic.toJsonStringKxs()
}

// https://github.com/enfein/mieru/blob/b1cd50fabb2f893c7878388767d97370dbb7a660/pkg/appctl/url.go#L51
fun parseMieru(link: String): MieruBean {
    val url = Libcore.parseURL(link)
    return MieruBean().apply {
        username = url.getUsername()
        password = url.getPassword()
        serverAddress = url.getHost()

        val ports = mutableListOf<String>()
        val rawUrl = url.getString()
        val query = rawUrl.substringAfter("?", "").substringBefore("#")
        if (query.isNotEmpty()) {
            query.split("&").forEach { pair ->
                val parts = pair.split("=", limit = 2)
                if (parts.size == 2 && parts[0] == "port") {
                    ports.add(parts[1])
                }
            }
        }

        if (ports.isNotEmpty()) {
            serverPorts = ports.joinToString(",")
            serverPort = ports.first().split("-").first().toIntOrNull() ?: defaultPort
        } else {
            serverPort = url.getPorts().toIntOrNull() ?: defaultPort
        }

        name = url.queryParameterNotBlank("profile") ?: ""
        protocol = (url.queryParameterNotBlank("protocol") ?: MieruBean.PROTOCOL_TCP).uppercase()
        mtu = url.queryParameterNotBlank("mtu")?.toIntOrNull() ?: 0
        serverMuxNumber = (url.queryParameterNotBlank("multiplexing") ?: url.queryParameterNotBlank("mux"))?.let {
            parseMieruMux(it)
        } ?: 0
        handshakeMode = (url.queryParameterNotBlank("handshake_mode") ?: url.queryParameterNotBlank("handshake-mode"))?.let {
            parseMieruHandshake(it)
        } ?: 0
        userHint = url.parseBoolean("user_hint") || url.parseBoolean("user-hint")
        trafficPattern = url.queryParameterNotBlank("traffic_pattern") ?: url.queryParameterNotBlank("traffic-pattern") ?: ""
    }
}

fun MieruBean.toUri(): String {
    val url = Libcore.newURL("mierus")
    url.setUsername(this.username)
    url.setPassword(this.password)
    url.setHost(this.serverAddress)

    if (this.serverPorts.isNotBlank()) {
        this.serverPorts.split(",").forEach {
            url.addQueryParameter("port", it)
        }
    } else {
        url.setPorts(this.serverPort.toString())
    }

    this.name.takeIf { it.isNotBlank() }?.let {
        url.addQueryParameter("profile", it)
    }
    if (this.protocol != MieruBean.PROTOCOL_TCP) {
        url.addQueryParameter("protocol", this.protocol.lowercase())
    }
    this.mtu.takeIf { it > 0 }?.let {
        url.addQueryParameter("mtu", it.toString())
    }
    this.serverMuxNumber.takeIf { it > 0 }?.let {
        url.addQueryParameter("multiplexing", mieruMuxToString(it) ?: "")
    }
    this.handshakeMode.takeIf { it > 0 }?.let {
        url.addQueryParameter("handshake-mode", mieruHandshakeToString(it) ?: "")
    }
    if (this.userHint) {
        url.addQueryParameter("user-hint", "true")
    }
    this.trafficPattern.blankAsNull()?.let { trafficPattern ->
        val base64TrafficPattern = runCatching {
            Libcore.encodeMieruTrafficPattern(trafficPattern)
        }.getOrElse {
            trafficPattern
        }
        url.addQueryParameter("traffic-pattern", base64TrafficPattern)
    }
    return url.getString()
}

internal fun parseMieruMux(link: String): Int? = when (link.uppercase()) {
    "MULTIPLEXING_DEFAULT", "DEFAULT" -> 0
    "MULTIPLEXING_OFF", "OFF" -> 1
    "MULTIPLEXING_LOW", "LOW" -> 2
    "MULTIPLEXING_MIDDLE", "MIDDLE", "MULTIPLEXING_MEDIUM", "MEDIUM" -> 3
    "MULTIPLEXING_HIGH", "HIGH" -> 4
    else -> link.toIntOrNull()
}

internal fun mieruMuxToString(level: Int): String? = when (level) {
    0 -> "MULTIPLEXING_DEFAULT"
    1 -> "MULTIPLEXING_OFF"
    2 -> "MULTIPLEXING_LOW"
    3 -> "MULTIPLEXING_MIDDLE"
    4 -> "MULTIPLEXING_HIGH"
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
            server_ports = bean.serverPorts.split(",").map { it.trim() }.toMutableList()
            server_port = null
        } else {
            server_port = bean.serverPort
            server_ports = null
        }
        transport = bean.protocol.uppercase()
        username = bean.username
        password = bean.password
        multiplexing = mieruMuxToString(bean.serverMuxNumber)
        handshake_mode = mieruHandshakeToString(bean.handshakeMode)
        user_hint = bean.userHint
        mtu = bean.mtu.takeIf { it > 0 }
        traffic_pattern = bean.trafficPattern.takeIf { it.isNotBlank() && it != "1" }
    }
}

fun parseMieruOutbound(json: JSONMap): MieruBean = MieruBean().apply {
    parseBoxOutbound(json) { key, value ->
        when (key) {
            "transport" -> protocol = value.toString().uppercase()
            "username" -> username = value.toString()
            "password" -> password = value.toString()
            "server_ports" -> serverPorts = (value as? List<*>)?.joinToString(",") ?: ""
            "multiplexing" -> serverMuxNumber = parseMieruMux(value.toString()) ?: 0
            "handshake_mode" -> handshakeMode = parseMieruHandshake(value.toString()) ?: 0
            "user_hint" -> userHint = value.toString().toBoolean()
            "mtu" -> mtu = value.toString().toIntOrNull() ?: 1400
            "traffic_pattern" -> trafficPattern = value.toString()
        }
    }
}

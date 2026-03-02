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

import fr.husi.ktx.blankAsNull
import fr.husi.database.DataStore
import fr.husi.fmt.LOCALHOST4
import fr.husi.fmt.SingBoxOptions
import fr.husi.fmt.parseBoxOutbound
import fr.husi.ktx.JSONMap
import fr.husi.ktx.queryParameterNotBlank
import fr.husi.ktx.toJsonMapKxs
import fr.husi.ktx.toJsonStringKxs
import fr.husi.libcore.Libcore
import fr.husi.logLevelString

fun MieruBean.buildMieruConfig(port: Int, logLevel: Int): String {
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
                        "portBindings" to listOf(
                            mapOf(
                                "port" to finalPort,
                                "protocol" to protocol.uppercase(),
                            ),
                        ),
                    ),
                ),
                "mtu" to mtu,
                "multiplexing" to mieruMuxToString(serverMuxNumber)?.let { mapOf("level" to it) },
                "handshakeMode" to mieruHandshakeToString(handshakeMode),
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
fun parseMieru(link: String): MieruBean = MieruBean().apply {
    val url = Libcore.parseURL(link)
    username = url.username
    password = url.password
    serverAddress = url.host
    serverPort = url.ports.toIntOrNull() ?: defaultPort

    name = url.queryParameter("profile")
    mtu = url.queryParameterNotBlank("mtu")?.toIntOrNull() ?: 0
    serverMuxNumber = url.queryParameter("multiplexing")?.let {
        parseMieruMux(it)
    } ?: 0
    handshakeMode = url.queryParameter("handshake_mode")?.let {
        parseMieruHandshake(it)
    } ?: 0
    trafficPattern = url.queryParameter("traffic-pattern")
}

fun MieruBean.toUri(): String = Libcore.newURL("mierus").apply {
    username = this@toUri.username
    password = this@toUri.password
    host = serverAddress
    ports = serverPort.toString()

    name.takeIf { it.isNotBlank() }?.let {
        addQueryParameter("profile", it)
    }
    mtu.takeIf { it > 0 }?.let {
        addQueryParameter("mtu", it.toString())
    }
    serverMuxNumber.takeIf { it > 0 }?.let {
        addQueryParameter("multiplexing", mieruMuxToString(it))
    }
    handshakeMode.takeIf { it > 0 }?.let {
        addQueryParameter("handshake_mode", mieruHandshakeToString(it))
    }
    trafficPattern.blankAsNull()?.let { trafficPattern ->
        val base64TrafficPattern = runCatching {
            Libcore.encodeMieruTrafficPattern(trafficPattern)
        }.getOrElse {
            trafficPattern
        }
        addQueryParameter("traffic-pattern", base64TrafficPattern)
    }
}.string

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
        server_port = bean.serverPort
        transport = bean.protocol.uppercase()
        username = bean.username
        password = bean.password
        multiplexing = mieruMuxToString(bean.serverMuxNumber)
        handshake_mode = mieruHandshakeToString(bean.handshakeMode)
        traffic_pattern = bean.trafficPattern.takeIf { it.isNotBlank() && it != "1" }
    }
}

fun parseMieruOutbound(json: JSONMap): MieruBean = MieruBean().apply {
    parseBoxOutbound(json) { key, value ->
        when (key) {
            "transport" -> protocol = value.toString().uppercase()
            "username" -> username = value.toString()
            "password" -> password = value.toString()
            "multiplexing" -> serverMuxNumber = parseMieruMux(value.toString()) ?: 0
            "handshake_mode" -> handshakeMode = parseMieruHandshake(value.toString()) ?: 0
            "traffic_pattern" -> trafficPattern = value.toString()
        }
    }
}

package fr.husi.fmt.trojan_go

import fr.husi.fmt.SingBoxOptions
import fr.husi.fmt.listable
import fr.husi.fmt.parseBoxOutbound
import fr.husi.fmt.parseBoxTLS
import fr.husi.ktx.JSONMap
import fr.husi.ktx.blankAsNull
import fr.husi.ktx.getBool
import fr.husi.ktx.getIntOrNull
import fr.husi.ktx.getObject
import fr.husi.ktx.getStr
import fr.husi.ktx.parseBoolean
import fr.husi.ktx.queryParameterNotBlank
import io.github.xchacha20_poly1305.kpuri.Url
import io.github.xchacha20_poly1305.kpuri.buildUrl
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

fun parseTrojanGo(link: String): TrojanGoBean = TrojanGoBean().apply {
    val url = Url.parse(link)
    serverAddress = url.host.orEmpty()
    serverPort = url.port?.toIntOrNull() ?: 443
    password = url.username.orEmpty().ifBlank { url.password.orEmpty() }
    name = url.fragment.orEmpty()

    url.queryParameterNotBlank("sni")?.let { sni = it }
    url.queryParameterNotBlank("peer")?.let { sni = it }

    url.queryParameterNotBlank("type")?.let {
        type = it
    }
    if (type == "ws") {
        url.queryParameterNotBlank("host")?.let { host = it }
        url.queryParameterNotBlank("path")?.let { path = it }
    }

    url.queryParameterNotBlank("encryption")?.let { enc ->
        encryption = enc
        if (enc.startsWith("ss;")) {
            val ssPart = enc.removePrefix("ss;")
            ssMethod = ssPart.substringBefore(":")
            ssPassword = ssPart.substringAfter(":")
        }
    }

    mux = url.parseBoolean("mux")
    url.queryParameterNotBlank("concurrency")?.toIntOrNull()?.let { muxConcurrency = it }
    allowInsecure = url.parseBoolean("allowInsecure")
}

fun TrojanGoBean.toUri(): String = buildUrl("trojan-go") {
    host = serverAddress
    if (serverPort in 1..65535) {
        port = serverPort.toString()
    }
    this@toUri.password.blankAsNull()?.let { username = it }

    sni.blankAsNull()?.let { addQueryParameter("sni", it) }
    if (this@toUri.type.isNotBlank() && this@toUri.type != "original") {
        addQueryParameter("type", this@toUri.type)
        if (this@toUri.type == "ws") {
            this@toUri.host.blankAsNull()?.let { addQueryParameter("host", it) }
            this@toUri.path.blankAsNull()?.let { addQueryParameter("path", it) }
        }
    }

    val hasSS = encryption.startsWith("ss;") || (ssMethod.isNotBlank() && ssPassword.isNotBlank())
    if (hasSS) {
        val encValue = if (encryption.startsWith("ss;")) encryption else "ss;$ssMethod:$ssPassword"
        addQueryParameter("encryption", encValue)
    }

    if (mux) {
        addQueryParameter("mux", "true")
        if (muxConcurrency != 8) {
            addQueryParameter("concurrency", muxConcurrency.toString())
        }
    }

    if (allowInsecure) {
        addQueryParameter("allowInsecure", "true")
    }

    name.blankAsNull()?.let { fragment = it }
}.toString()

fun buildSingBoxOutboundTrojanGoBean(bean: TrojanGoBean): SingBoxOptions.Outbound_TrojanGoOptions {
    return SingBoxOptions.Outbound_TrojanGoOptions().apply {
        type = SingBoxOptions.TYPE_TROJAN_GO
        server = bean.serverAddress
        server_port = bean.serverPort
        password = bean.password
        network = bean.network().split(",").toMutableList()

        tls = SingBoxOptions.OutboundTLSOptions().apply {
            enabled = true
            server_name = bean.sni.ifBlank { bean.serverAddress }
            insecure = bean.allowInsecure
        }

        if (bean.type == "ws") {
            val wsHost = bean.host.ifBlank { bean.sni.ifBlank { bean.serverAddress } }
            val wsHeaders = buildJsonObject {
                if (wsHost.isNotBlank()) {
                    put("Host", wsHost)
                }
            }
            transport = buildJsonObject {
                put("type", "ws")
                put("path", if (bean.path.startsWith("/")) bean.path else "/${bean.path}")
                if (wsHost.isNotBlank()) {
                    put("headers", wsHeaders)
                }
            }
        }

        val hasSS = bean.encryption.startsWith("ss;") || (bean.ssMethod.isNotBlank() && bean.ssPassword.isNotBlank())
        if (hasSS) {
            val method = if (bean.encryption.startsWith("ss;")) {
                bean.encryption.substringAfter(";").substringBefore(":")
            } else {
                bean.ssMethod
            }
            val pass = if (bean.encryption.startsWith("ss;")) {
                bean.encryption.substringAfter(":")
            } else {
                bean.ssPassword
            }
            shadowsocks = SingBoxOptions.TrojanGoShadowsocksOptions().apply {
                enabled = true
                this.method = method
                this.password = pass
            }
        }

        if (bean.mux) {
            mux = SingBoxOptions.TrojanGoMuxOptions().apply {
                enabled = true
                concurrency = if (bean.muxConcurrency > 0) bean.muxConcurrency else 8
                idle_timeout = 60
            }
        }
    }
}

fun parseTrojanGoOutbound(json: JSONMap): TrojanGoBean = TrojanGoBean().apply {
    parseBoxOutbound(json) { key, value ->
        when (key) {
            "password" -> password = value.toString()
            "network" -> {
                val netList = listable<String>(value)
                if (netList != null) {
                    udp = netList.contains("udp")
                }
            }
        }
    }

    json.getObject("tls")?.let { tlsMap ->
        val tlsOpts = parseBoxTLS(tlsMap)
        sni = tlsOpts.server_name.orEmpty()
        allowInsecure = tlsOpts.insecure ?: false
    }

    json.getObject("transport")?.let { transportMap ->
        if (transportMap.getStr("type") == "ws") {
            type = "ws"
            path = transportMap.getStr("path").orEmpty()
            transportMap.getObject("headers")?.let { headersMap ->
                host = headersMap.getStr("Host").orEmpty()
            }
        }
    }

    json.getObject("shadowsocks")?.let { ssMap ->
        if (ssMap.getBool("enabled") == true) {
            ssMethod = ssMap.getStr("method").orEmpty()
            ssPassword = ssMap.getStr("password").orEmpty()
            encryption = "ss;$ssMethod:$ssPassword"
        }
    }

    json.getObject("mux")?.let { muxMap ->
        if (muxMap.getBool("enabled") == true) {
            mux = true
            muxConcurrency = muxMap.getIntOrNull("concurrency") ?: 8
        }
    }
}

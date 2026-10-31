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
    val scheme = url.scheme?.lowercase()
    if (scheme == "trojan") {
        require(link.contains("encryption=ss") || link.contains("plugin=trojan-go")) {
            "standard trojan link is not a trojan-go link"
        }
    } else {
        require(scheme == "trojan-go" || scheme == "trojango") {
            "url does not have a trojan-go:// scheme"
        }
    }

    val rawUser = url.username.orEmpty()
    require(rawUser.isNotEmpty()) { "no password specified" }
    require(url.encodedPassword == null) { "password possibly missing percentage encoding for colon" }
    password = rawUser

    val rawHost = url.host.orEmpty()
    require(rawHost.isNotEmpty()) { "host is empty" }
    serverAddress = rawHost

    val portStr = url.port
    serverPort = if (portStr.isNullOrEmpty()) {
        443
    } else {
        val p = portStr.toIntOrNull()
        require(p != null && p in 1..65535) { "invalid port $portStr" }
        p
    }

    name = url.fragment.orEmpty()

    val snis = url.queryParameterValues("sni")
    if (snis.isNotEmpty()) {
        require(snis.size == 1) { "multiple SNIs" }
        require(snis[0].isNotEmpty()) { "empty SNI" }
        sni = snis[0]
    } else {
        val peers = url.queryParameterValues("peer")
        if (peers.isNotEmpty()) {
            require(peers.size == 1) { "multiple SNIs" }
            require(peers[0].isNotEmpty()) { "empty SNI" }
            sni = peers[0]
        } else {
            sni = serverAddress
        }
    }

    val types = url.queryParameterValues("type")
    if (types.isNotEmpty()) {
        require(types.size == 1) { "multiple transport types" }
        val t = types[0]
        require(t.isNotEmpty()) { "empty transport type" }
        require(t == "original" || t == "ws") { "unknown transport type: $t" }
        type = t
    } else {
        type = "original"
    }

    val hosts = url.queryParameterValues("host")
    if (hosts.isNotEmpty()) {
        require(hosts.size == 1) { "multiple hosts" }
        val h = hosts[0]
        require(h.isNotEmpty()) { "empty host" }
        host = h
    } else {
        host = serverAddress
    }

    if (type == "ws") {
        val paths = url.queryParameterValues("path")
        require(paths.isNotEmpty()) { "path is required in websocket" }
        require(paths.size == 1) { "multiple paths" }
        val p = paths[0]
        require(p.isNotEmpty()) { "empty path" }
        require(p.startsWith("/")) { "path must start with /" }
        path = p
    } else {
        val paths = url.queryParameterValues("path")
        if (paths.isNotEmpty() && paths[0].isNotEmpty()) {
            path = paths[0]
        }
    }

    val encs = url.queryParameterValues("encryption")
    if (encs.isNotEmpty()) {
        require(encs.size == 1) { "multiple encryption fields" }
        val enc = encs[0]
        require(enc.isNotEmpty()) { "empty encryption" }
        val parts = enc.split(';', limit = 2)
        val provider = parts[0]
        require(provider == "ss" || provider == "none") { "unsupported encryption provider name: $provider" }
        encryption = enc
        if (provider == "ss") {
            require(parts.size >= 2) { "missing ss password" }
            val ssParams = parts[1].split(':', limit = 2)
            require(ssParams.size >= 2) { "missing ss password" }
            val method = ssParams[0]
            val pass = ssParams[1]
            require(method in setOf("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305")) {
                "unsupported ss method: $method"
            }
            require(pass.isNotEmpty()) { "ss password cannot be empty" }
            ssMethod = method
            ssPassword = pass
        }
    } else {
        encryption = "none"
    }

    val plugins = url.queryParameterValues("plugin")
    if (plugins.isNotEmpty()) {
        require(plugins.size == 1) { "multiple plugins" }
        val pl = plugins[0]
        require(pl.isNotEmpty()) { "empty plugin" }
        plugin = pl
    }

    mux = url.parseBoolean("mux")
    url.queryParameterNotBlank("concurrency")?.toIntOrNull()?.let {
        if (it > 0) muxConcurrency = it
    }
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
            this@toUri.path.blankAsNull()?.let {
                val wsPath = if (it.startsWith("/")) it else "/$it"
                addQueryParameter("path", wsPath)
            }
        }
    }

    val hasSS = encryption.startsWith("ss;") || (ssMethod.isNotBlank() && ssPassword.isNotBlank())
    if (hasSS) {
        val encValue = if (encryption.startsWith("ss;")) encryption else "ss;$ssMethod:$ssPassword"
        addQueryParameter("encryption", encValue)
    }

    plugin.blankAsNull()?.let { addQueryParameter("plugin", it) }

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

        if (bean.plugin.isNotBlank()) {
            plugin = bean.plugin
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

    json.getStr("plugin")?.let {
        plugin = it
    }
}

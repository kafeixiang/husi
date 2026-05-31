package fr.husi.fmt.snell

import fr.husi.fmt.SingBoxOptions
import fr.husi.fmt.parseBoxOutbound
import fr.husi.ktx.JSONMap
import fr.husi.ktx.parseBoolean
import fr.husi.libcore.Libcore
import fr.husi.ui.profile.muxTypes

fun parseSnell(link: String): SnellBean = SnellBean().apply {
    val url = Libcore.parseURL(link)
    serverAddress = url.host
    serverPort = url.ports.toIntOrNull() ?: 443
    val u = url.username
    psk = if (u.isNotEmpty()) u else url.password
    
    val f = url.fragment
    val qRemark = url.queryParameter("remark")
    val remark = if (qRemark.isNotEmpty()) qRemark else url.queryParameter("name")
    name = if (f.isNotEmpty()) f else remark
    
    version = url.queryParameter("version").toIntOrNull() ?: 4
    
    val o1 = url.queryParameter("obfs")
    val o2 = url.queryParameter("obfs-type")
    val o3 = url.queryParameter("obfs-mode")
    val o = if (o1.isNotEmpty()) o1 else if (o2.isNotEmpty()) o2 else o3
    obfsType = if (o.isNotEmpty()) o else "none"
    
    val h1 = url.queryParameter("obfs-host")
    val h2 = url.queryParameter("host")
    obfsHost = if (h1.isNotEmpty()) h1 else h2
    
    val udpParam = url.queryParameter("udp")
    udp = if (udpParam.isEmpty()) true else url.parseBoolean("udp")
    reuse = url.parseBoolean("reuse")
    
    // 如果混淆是 tls，则自动开启 tls 传输并重定向 SNI
    tls = url.parseBoolean("tls") || (url.scheme == "snells") || (obfsType == "tls")
    
    val s1 = url.queryParameter("sni")
    val s2 = url.queryParameter("peer")
    sni = if (s1.isNotEmpty()) s1 else if (s2.isNotEmpty()) s2 else if (obfsType == "tls") obfsHost else ""
    
    allowInsecure = url.parseBoolean("allowInsecure") || url.parseBoolean("insecure")
    udpOverTcp = url.parseBoolean("udp-over-tcp") || url.parseBoolean("uot")
}

fun SnellBean.toUri(): String {
    val url = Libcore.newURL(if (tls) "snells" else "snell")
    url.username = psk
    url.host = serverAddress
    url.ports = serverPort.toString()

    if (name.isNotEmpty()) {
        url.fragment = name
    }
    url.addQueryParameter("version", version.toString())
    if (obfsType != "none") {
        url.addQueryParameter("obfs", obfsType)
        if (obfsHost.isNotEmpty()) url.addQueryParameter("obfs-host", obfsHost)
    }
    if (!udp) {
        url.addQueryParameter("udp", "false")
    }
    if (reuse) {
        url.addQueryParameter("reuse", "true")
    }
    if (tls) {
        if (sni.isNotEmpty()) url.addQueryParameter("sni", sni)
        if (allowInsecure) url.addQueryParameter("allowInsecure", "true")
    }
    if (udpOverTcp) {
        url.addQueryParameter("udp-over-tcp", "true")
    }
    return url.string
}

fun buildSingBoxOutboundSnellBean(bean: SnellBean): SingBoxOptions.Outbound_SnellOptions {
    return SingBoxOptions.Outbound_SnellOptions().apply {
        type = SingBoxOptions.TYPE_SNELL
        server = bean.serverAddress
        server_port = bean.serverPort
        psk = bean.psk
        version = bean.version
        reuse = bean.reuse && bean.version >= 4
        network = bean.network().split(",").toMutableList()
        
        // V5 强制忽略所有 TCP 传输层设置 (OBFS, TLS, Mux, UoT)
        if (bean.version < 5) {
            // OBFS (HTTP) 映射
            if (bean.obfsType != "none" && bean.obfsType != "tls") {
                obfs = SingBoxOptions.SnellObfsOptions().apply {
                    type = bean.obfsType
                    host = bean.obfsHost.takeIf { it.isNotEmpty() }
                }
            }

            // TLS 映射
            if (bean.tls || bean.obfsType == "tls") {
                tls = SingBoxOptions.OutboundTLSOptions().apply {
                    enabled = true
                    server_name = if (bean.sni.isNotEmpty()) bean.sni else if (bean.obfsType == "tls") bean.obfsHost else null
                    insecure = bean.allowInsecure.takeIf { it }
                }
            }

            // UoT (UDP over TCP)
            if (bean.udpOverTcp) {
                udp_over_tcp = SingBoxOptions.UDPOverTCPOptions().apply {
                    enabled = true
                    version = 2
                }
            }

            // Multiplex (只有在 V4 以下或关闭 Reuse 时才有意义)
            if (bean.serverMux && !(bean.version >= 4 && bean.reuse)) {
                multiplex = SingBoxOptions.OutboundMultiplexOptions().apply {
                    enabled = true
                    protocol = muxTypes[bean.serverMuxType]
                    max_connections = bean.serverMuxNumber
                    padding = bean.serverMuxPadding
                }
            }
        }
    }
}

fun parseSnellOutbound(json: JSONMap): SnellBean = SnellBean().apply {
    parseBoxOutbound(json) { key, value ->
        when (key) {
            "psk" -> psk = value.toString()
            "version" -> version = (value as? Number)?.toInt() ?: 4
            "udp" -> udp = value.toString().toBoolean()
            "reuse" -> reuse = value.toString().toBoolean()
            "network" -> {
                val netList = value as? List<*>
                udp = netList?.contains("udp") ?: true
            }
            "obfs" -> {
                val obfsMap = value as? Map<*, *>
                obfsType = obfsMap?.get("type")?.toString() ?: "none"
                obfsHost = obfsMap?.get("host")?.toString() ?: ""
            }
            "tls" -> {
                val tlsMap = value as? Map<*, *>
                tls = tlsMap?.get("enabled")?.toString()?.toBoolean() ?: false
                sni = tlsMap?.get("server_name")?.toString() ?: ""
                allowInsecure = tlsMap?.get("insecure")?.toString()?.toBoolean() ?: false
            }
            "multiplex" -> {
                val muxMap = value as? Map<*, *>
                serverMux = muxMap?.get("enabled")?.toString()?.toBoolean() ?: false
                val protocol = muxMap?.get("protocol")?.toString()
                serverMuxType = muxTypes.indexOf(protocol).takeIf { it != -1 } ?: 0
                serverMuxNumber = (muxMap?.get("max_connections") as? Number)?.toInt() ?: 8
                serverMuxPadding = muxMap?.get("padding")?.toString()?.toBoolean() ?: false
            }
            "udp_over_tcp" -> {
                val uotMap = value as? Map<*, *>
                udpOverTcp = uotMap?.get("enabled")?.toString()?.toBoolean() ?: false
            }
        }
    }
}

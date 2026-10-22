package fr.husi.fmt.clash

import fr.husi.fmt.AbstractBean
import fr.husi.fmt.anytls.AnyTLSBean
import fr.husi.fmt.direct.DirectBean
import fr.husi.fmt.http.HttpBean
import fr.husi.fmt.hysteria.HysteriaBean
import fr.husi.fmt.juicity.JuicityBean
import fr.husi.fmt.masque.MASQUEBean
import fr.husi.fmt.mieru.MieruBean
import fr.husi.fmt.naive.NaiveBean
import fr.husi.fmt.shadowquic.ShadowQUICBean
import fr.husi.fmt.shadowsocks.ShadowsocksBean
import fr.husi.fmt.shadowsocks.pluginToLocal
import fr.husi.fmt.shadowtls.ShadowTLSBean
import fr.husi.fmt.snell.SnellBean
import fr.husi.fmt.socks.SOCKSBean
import fr.husi.fmt.ssh.SSHBean
import fr.husi.fmt.ssr.SSRBean
import fr.husi.fmt.trojan.TrojanBean
import fr.husi.fmt.trusttunnel.TrustTunnelBean
import fr.husi.fmt.tuic.TuicBean
import fr.husi.fmt.v2ray.StandardV2RayBean
import fr.husi.fmt.v2ray.VLESSBean
import fr.husi.fmt.v2ray.VMessBean
import fr.husi.fmt.v2ray.setTLS
import fr.husi.fmt.wireguard.WireGuardBean
import fr.husi.ktx.Logs
import fr.husi.ktx.blankAsNull
import fr.husi.ktx.kxs
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

fun JsonElement.toAny(): Any = when (this) {
    is JsonObject -> mapValues { it.value.toAny() }
    is JsonArray -> map { it.toAny() }
    is JsonPrimitive -> {
        if (isString) content
        else booleanOrNull ?: longOrNull ?: doubleOrNull ?: content
    }
}

fun parseClashConfig(text: String): List<AbstractBean>? {
    val trimmed = text.trim()
    if (trimmed.isEmpty()) return null

    // 1. Quantumult X configuration ([server_local] section)
    if (trimmed.contains("[server_local]", ignoreCase = true)) {
        val qxBeans = parseQuantumultXSection(trimmed)
        if (qxBeans.isNotEmpty()) return qxBeans
    }

    // 2. Surge / Shadowrocket / Loon configuration ([Proxy] section)
    if (trimmed.contains("[Proxy]", ignoreCase = true)) {
        val surgeBeans = parseSurgeSection(trimmed)
        if (surgeBeans.isNotEmpty()) return surgeBeans
    }

    // 3. Standalone Surge / Shadowrocket / Loon or Quantumult X line lists
    val nonCommentLines = trimmed.lines().map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") && !it.startsWith(";") && !it.startsWith("//") }
    if (nonCommentLines.isNotEmpty()) {
        val qxCount = nonCommentLines.count { isQuantumultXLine(it) }
        if (qxCount > 0 && qxCount.toDouble() / nonCommentLines.size >= 0.6) {
            val qxBeans = nonCommentLines.mapNotNull { parseQuantumultXLine(it) }
            if (qxBeans.isNotEmpty()) return qxBeans
        }

        val surgeCount = nonCommentLines.count { isSurgeProxyLine(it) }
        if (surgeCount > 0 && surgeCount.toDouble() / nonCommentLines.size >= 0.6) {
            val surgeBeans = nonCommentLines.mapNotNull { parseSurgeLine(it) }
            if (surgeBeans.isNotEmpty()) return surgeBeans
        }
    }

    // 4. Clash / Mihomo YAML & JSON format
    val parsedObj = try {
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            kxs.parseToJsonElement(trimmed).toAny()
        } else {
            YamlParser.parse(trimmed)
        }
    } catch (e: Exception) {
        Logs.d("Clash parser failed to parse input", e)
        null
    } ?: return null

    val proxyMaps = mutableListOf<Map<String, Any?>>()

    when (parsedObj) {
        is Map<*, *> -> {
            @Suppress("UNCHECKED_CAST")
            val map = parsedObj as Map<String, Any?>
            val rawProxies = map["proxies"] ?: map["Proxy"] ?: map["outbounds"]
            if (rawProxies is List<*>) {
                for (item in rawProxies) {
                    if (item is Map<*, *>) {
                        @Suppress("UNCHECKED_CAST")
                        proxyMaps.add(item as Map<String, Any?>)
                    }
                }
            } else if (map.containsKey("type") && (map.containsKey("server") || map.containsKey("host"))) {
                proxyMaps.add(map)
            }
        }
        is List<*> -> {
            for (item in parsedObj) {
                if (item is Map<*, *>) {
                    @Suppress("UNCHECKED_CAST")
                    proxyMaps.add(item as Map<String, Any?>)
                }
            }
        }
    }

    if (proxyMaps.isEmpty()) return null

    val beans = proxyMaps.mapNotNull { parseClashProxy(it) }
    return beans.ifEmpty { null }
}

fun parseClashProxy(map: Map<String, Any?>): AbstractBean? {
    val type = map.getStr("type")?.lowercase() ?: return null
    val name = map.getStr("name") ?: map.getStr("tag") ?: ""
    val server = map.getStr("server") ?: map.getStr("host") ?: ""
    val port = map.getInt("port") ?: 0

    val bean: AbstractBean = when (type) {
        "ss", "shadowsocks" -> {
            ShadowsocksBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.method = map.getStr("cipher") ?: map.getStr("method") ?: ""
                this.password = map.getStr("password") ?: ""
                this.udpOverTcp = map.getBool("udp-over-tcp") ?: false

                val pluginStr = map.getStr("plugin")
                val pluginOpts = map.getMap("plugin-opts") ?: map.getMap("plugin_opts")
                if (pluginStr != null && pluginOpts != null) {
                    val optsStr = pluginOpts.entries.joinToString(";") { "${it.key}=${it.value}" }
                    this.plugin = "$pluginStr;$optsStr"
                } else if (pluginStr != null) {
                    this.plugin = pluginStr
                }
                pluginToLocal()
            }
        }

        "ssr", "shadowsocksr" -> {
            SSRBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.method = map.getStr("cipher") ?: map.getStr("method") ?: ""
                this.password = map.getStr("password") ?: ""
                this.protocol = map.getStr("protocol") ?: ""
                this.protocolParam = map.getStr("protocol-param") ?: map.getStr("protocolparam") ?: map.getStr("protocol_param") ?: ""
                this.obfs = map.getStr("obfs") ?: ""
                this.obfsParam = map.getStr("obfs-param") ?: map.getStr("obfsparam") ?: map.getStr("obfs_param") ?: ""
            }
        }

        "vmess" -> {
            VMessBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.uuid = map.getStr("uuid") ?: ""
                this.alterId = map.getInt("alterId") ?: map.getInt("aid") ?: 0
                this.security = map.getStr("cipher") ?: map.getStr("security") ?: "auto"

                val tls = map.getBool("tls") == true
                val sni = map.getStr("servername") ?: map.getStr("sni") ?: ""
                setTLS(tls)
                if (sni.isNotBlank()) this.sni = sni

                this.allowInsecure = map.getBool("skip-cert-verify") == true

                val network = map.getStr("network") ?: "tcp"
                this.v2rayTransport = network

                val wsOpts = map.getMap("ws-opts")
                val wsPath = map.getStr("ws-path") ?: wsOpts?.getStr("path")
                val wsHeaders = wsOpts?.getMap("headers")
                if (wsPath != null) this.path = wsPath
                if (wsHeaders != null) {
                    val host = wsHeaders.getStr("Host") ?: wsHeaders.getStr("host")
                    if (host != null) this.host = host
                }

                val grpcOpts = map.getMap("grpc-opts")
                val serviceName = grpcOpts?.getStr("grpc-service-name") ?: grpcOpts?.getStr("serviceName")
                if (serviceName != null) this.path = serviceName

                val h2Opts = map.getMap("h2-opts") ?: map.getMap("http-opts")
                if (h2Opts != null) {
                    val h2Path = h2Opts.getStr("path")
                    if (h2Path != null) this.path = h2Path
                    val h2Host = h2Opts.getStr("host") ?: (h2Opts["host"] as? List<*>)?.firstOrNull()?.toString()
                    if (h2Host != null) this.host = h2Host
                }

                val realityOpts = map.getMap("reality-opts")
                if (realityOpts != null) {
                    this.realityPublicKey = realityOpts.getStr("public-key") ?: ""
                    this.realityShortID = realityOpts.getStr("short-id") ?: ""
                }

                val fp = map.getStr("client-fingerprint") ?: map.getStr("fingerprint")
                if (fp != null) this.utlsFingerprint = fp
                val alpnList = map.getStrList("alpn")
                if (alpnList != null) this.alpn = alpnList.joinToString(",")
            }
        }

        "vless" -> {
            VLESSBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.uuid = map.getStr("uuid") ?: map.getStr("password") ?: ""
                this.flow = map.getStr("flow") ?: ""

                val tls = map.getBool("tls") == true || map.containsKey("reality-opts") || map.containsKey("public-key") || map.containsKey("pbk")
                val sni = map.getStr("servername") ?: map.getStr("sni") ?: ""
                setTLS(tls)
                if (sni.isNotBlank()) this.sni = sni

                this.allowInsecure = map.getBool("skip-cert-verify") == true

                val network = map.getStr("network") ?: "tcp"
                this.v2rayTransport = network

                val wsOpts = map.getMap("ws-opts")
                val wsPath = map.getStr("ws-path") ?: wsOpts?.getStr("path")
                val wsHeaders = wsOpts?.getMap("headers")
                if (wsPath != null) this.path = wsPath
                if (wsHeaders != null) {
                    val host = wsHeaders.getStr("Host") ?: wsHeaders.getStr("host")
                    if (host != null) this.host = host
                }

                val grpcOpts = map.getMap("grpc-opts")
                val serviceName = grpcOpts?.getStr("grpc-service-name") ?: grpcOpts?.getStr("serviceName")
                if (serviceName != null) this.path = serviceName

                val h2Opts = map.getMap("h2-opts") ?: map.getMap("http-opts")
                if (h2Opts != null) {
                    val h2Path = h2Opts.getStr("path")
                    if (h2Path != null) this.path = h2Path
                    val h2Host = h2Opts.getStr("host") ?: (h2Opts["host"] as? List<*>)?.firstOrNull()?.toString()
                    if (h2Host != null) this.host = h2Host
                }

                val realityOpts = map.getMap("reality-opts")
                val pubKey = realityOpts?.getStr("public-key") ?: map.getStr("public-key") ?: map.getStr("pbk")
                if (pubKey != null) this.realityPublicKey = pubKey
                val shortId = realityOpts?.getStr("short-id") ?: map.getStr("short-id") ?: map.getStr("sid")
                if (shortId != null) this.realityShortID = shortId

                val fp = map.getStr("client-fingerprint") ?: map.getStr("fingerprint") ?: map.getStr("fp")
                if (fp != null) this.utlsFingerprint = fp
                val alpnList = map.getStrList("alpn")
                if (alpnList != null) this.alpn = alpnList.joinToString(",")

                val packetEncoding = map.getStr("packet-encoding")
                if (packetEncoding != null) {
                    when (packetEncoding.lowercase()) {
                        "packetaddr" -> this.packetEncoding = StandardV2RayBean.PACKET_ENCODING_PACKETADDR
                        "xudp" -> this.packetEncoding = StandardV2RayBean.PACKET_ENCODING_XUDP
                        "none" -> this.packetEncoding = StandardV2RayBean.PACKET_ENCODING_NONE
                    }
                }
            }
        }

        "trojan" -> {
            TrojanBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.password = map.getStr("password") ?: ""
                val sni = map.getStr("sni") ?: map.getStr("servername") ?: ""
                if (sni.isNotBlank()) this.sni = sni
                this.allowInsecure = map.getBool("skip-cert-verify") == true

                val network = map.getStr("network")
                if (network != null) this.v2rayTransport = network

                val wsOpts = map.getMap("ws-opts")
                val wsPath = wsOpts?.getStr("path")
                if (wsPath != null) this.path = wsPath

                val grpcOpts = map.getMap("grpc-opts")
                val serviceName = grpcOpts?.getStr("grpc-service-name") ?: grpcOpts?.getStr("serviceName")
                if (serviceName != null) this.path = serviceName

                val fp = map.getStr("client-fingerprint") ?: map.getStr("fingerprint")
                if (fp != null) this.utlsFingerprint = fp
                val alpnList = map.getStrList("alpn")
                if (alpnList != null) this.alpn = alpnList.joinToString(",")
            }
        }

        "hysteria", "hysteria1" -> {
            HysteriaBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPorts = map.getStr("ports") ?: (if (port > 0) port.toString() else "443")
                this.protocolVersion = HysteriaBean.PROTOCOL_VERSION_1

                val auth = map.getStr("auth") ?: map.getStr("auth_str") ?: map.getStr("auth-str") ?: ""
                this.authPayload = auth

                this.sni = map.getStr("sni") ?: map.getStr("servername") ?: ""
                this.obfsType = map.getStr("obfs") ?: ""
                this.allowInsecure = map.getBool("skip-cert-verify") == true

                val alpnList = map.getStrList("alpn")
                if (alpnList != null) {
                    this.alpn = alpnList.joinToString(",")
                }
            }
        }

        "hysteria2", "hy2" -> {
            HysteriaBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPorts = map.getStr("ports") ?: (if (port > 0) port.toString() else "443")
                this.protocolVersion = HysteriaBean.PROTOCOL_VERSION_2

                val pass = map.getStr("password") ?: map.getStr("auth") ?: ""
                this.authPayload = pass

                this.sni = map.getStr("sni") ?: map.getStr("servername") ?: ""
                this.obfsType = map.getStr("obfs") ?: ""
                this.obfsPassword = map.getStr("obfs-password") ?: map.getStr("obfs_password") ?: ""
                this.allowInsecure = map.getBool("skip-cert-verify") == true

                val alpnList = map.getStrList("alpn")
                if (alpnList != null) {
                    this.alpn = alpnList.joinToString(",")
                }
            }
        }

        "tuic" -> {
            TuicBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.token = map.getStr("token") ?: map.getStr("password") ?: ""
                this.uuid = map.getStr("uuid") ?: ""
                this.sni = map.getStr("sni") ?: map.getStr("servername") ?: ""
                this.congestionController = map.getStr("congestion-controller") ?: map.getStr("congestion_controller") ?: "bbr"
                this.udpRelayMode = map.getStr("udp-relay-mode") ?: map.getStr("udp_relay_mode") ?: "native"
                this.zeroRTT = map.getBool("zero-rtt-handshake") ?: false
                this.allowInsecure = map.getBool("skip-cert-verify") == true

                val alpnList = map.getStrList("alpn")
                if (alpnList != null) {
                    this.alpn = alpnList.joinToString(",")
                }
            }
        }

        "juicity" -> {
            JuicityBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.uuid = map.getStr("user_id") ?: map.getStr("uuid") ?: ""
                this.password = map.getStr("pin") ?: map.getStr("password") ?: ""
                this.sni = map.getStr("sni") ?: map.getStr("servername") ?: ""
                this.pinSHA256 = map.getStr("pinned-certchain-sha256") ?: ""
                this.allowInsecure = map.getBool("skip-cert-verify") == true
            }
        }

        "socks5", "socks", "socks4" -> {
            SOCKSBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.username = map.getStr("username") ?: ""
                this.password = map.getStr("password") ?: ""
                this.protocol = if (type == "socks4") SOCKSBean.PROTOCOL_SOCKS4 else SOCKSBean.PROTOCOL_SOCKS5
            }
        }

        "http", "https" -> {
            HttpBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.username = map.getStr("username") ?: ""
                this.password = map.getStr("password") ?: ""
                setTLS(type == "https" || map.getBool("tls") == true)
                val sni = map.getStr("sni") ?: map.getStr("servername") ?: ""
                if (sni.isNotBlank()) this.sni = sni
            }
        }

        "wireguard" -> {
            WireGuardBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.privateKey = map.getStr("private-key") ?: ""
                this.publicKey = map.getStr("public-key") ?: ""
                this.preSharedKey = map.getStr("preshared-key") ?: ""
                val ipVal = map["ip"] ?: map["ip-addresses"] ?: map["addresses"]
                if (ipVal is List<*>) {
                    this.localAddress = ipVal.joinToString(",") { it.toString() }
                } else if (ipVal != null) {
                    this.localAddress = ipVal.toString()
                }
                val mtuVal = map.getInt("mtu")
                if (mtuVal != null && mtuVal > 0) this.mtu = mtuVal
            }
        }

        "snell" -> {
            SnellBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.psk = map.getStr("psk") ?: map.getStr("password") ?: ""
                this.version = map.getInt("version") ?: SnellBean.VERSION_4

                val obfsOpts = map.getMap("obfs-opts")
                if (obfsOpts != null) {
                    this.obfsMode = obfsOpts.getStr("mode") ?: ""
                    this.obfsHost = obfsOpts.getStr("host") ?: ""
                }
            }
        }

        "shadow-tls", "shadowtls" -> {
            ShadowTLSBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.password = map.getStr("password") ?: ""
                val sni = map.getStr("sni") ?: map.getStr("servername") ?: ""
                if (sni.isNotBlank()) this.sni = sni
                this.protocolVersion = map.getInt("version") ?: 3
            }
        }

        "anytls" -> {
            AnyTLSBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.password = map.getStr("password") ?: ""
                this.serverName = map.getStr("sni") ?: map.getStr("servername") ?: ""
                this.allowInsecure = map.getBool("skip-cert-verify") == true
                val alpnList = map.getStrList("alpn")
                if (alpnList != null) this.alpn = alpnList.joinToString(",")
                val fp = map.getStr("client-fingerprint") ?: map.getStr("fingerprint")
                if (fp != null) this.utlsFingerprint = fp
            }
        }

        "trusttunnel", "trust-tunnel" -> {
            TrustTunnelBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.username = map.getStr("username") ?: ""
                this.password = map.getStr("password") ?: ""
                this.serverName = map.getStr("sni") ?: map.getStr("servername") ?: ""
                this.quic = map.getBool("quic") == true
                this.allowInsecure = map.getBool("skip-cert-verify") == true
                val alpnList = map.getStrList("alpn")
                if (alpnList != null) this.alpn = alpnList.joinToString(",")
                val fp = map.getStr("client-fingerprint") ?: map.getStr("fingerprint")
                if (fp != null) this.utlsFingerprint = fp
            }
        }

        "naive", "naiveproxy" -> {
            NaiveBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.username = map.getStr("username") ?: ""
                this.password = map.getStr("password") ?: ""
                this.sni = map.getStr("sni") ?: map.getStr("servername") ?: ""
                val isQuic = map.getBool("quic") == true || map.getStr("proto")?.lowercase() == "quic"
                this.proto = if (isQuic) NaiveBean.PROTO_QUIC else NaiveBean.PROTO_HTTPS
                this.insecureConcurrency = map.getInt("insecure-concurrency") ?: 0
                this.extraHeaders = map.getStr("extra-headers") ?: ""
            }
        }

        "ssh" -> {
            SSHBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.username = map.getStr("username") ?: "root"
                this.password = map.getStr("password") ?: ""
                this.privateKey = map.getStr("private-key") ?: ""
                this.privateKeyPassphrase = map.getStr("passphrase") ?: ""
                this.publicKey = map.getStr("public-key") ?: ""
                this.authType = if (this.privateKey.isNotBlank()) SSHBean.AUTH_TYPE_PRIVATE_KEY else SSHBean.AUTH_TYPE_PASSWORD
            }
        }

        "masque", "masque-surge" -> {
            MASQUEBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.username = map.getStr("username") ?: ""
                this.password = map.getStr("password") ?: ""
                this.path = map.getStr("path") ?: ""
                this.serverName = map.getStr("sni") ?: map.getStr("servername") ?: ""
                this.allowInsecure = map.getBool("skip-cert-verify") == true
                val alpnList = map.getStrList("alpn")
                if (alpnList != null) this.alpn = alpnList.joinToString(",")
                val fp = map.getStr("client-fingerprint") ?: map.getStr("fingerprint")
                if (fp != null) this.utlsFingerprint = fp
            }
        }

        "direct" -> {
            DirectBean().apply {
                this.name = name
            }
        }

        "shadowquic" -> {
            ShadowQUICBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.password = map.getStr("password") ?: ""
                this.sni = map.getStr("sni") ?: map.getStr("servername") ?: ""
            }
        }

        "mieru" -> {
            MieruBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.username = map.getStr("username") ?: ""
                this.password = map.getStr("password") ?: ""
                this.protocol = (map.getStr("transport") ?: "tcp").uppercase()
            }
        }

        else -> return null
    }

    bean.initializeDefaultValues()
    return bean
}

// ==================== Surge / Shadowrocket / Loon Parsers ====================

private val SURGE_PROXY_TYPES = setOf(
    "ss", "shadowsocks", "ssr", "shadowsocksr",
    "vmess", "vless", "trojan",
    "hysteria", "hysteria1", "hysteria2", "hy2",
    "tuic", "snell", "wireguard",
    "socks5", "socks5-tls", "socks",
    "http", "https",
    "anytls", "trust-tunnel", "trusttunnel", "naive", "ssh", "masque",
    "mieru", "juicity", "shadowquic", "direct"
)

fun isSurgeProxyLine(line: String): Boolean {
    val equalsIdx = line.indexOf('=')
    if (equalsIdx <= 0) return false
    val right = line.substring(equalsIdx + 1).trim()
    val firstToken = right.substringBefore(',').trim().lowercase()
    if (firstToken == "direct") return true
    return firstToken in SURGE_PROXY_TYPES && right.contains(',')
}

fun parseSurgeSection(text: String): List<AbstractBean> {
    val lines = text.lines()
    var inProxySection = false
    val beans = mutableListOf<AbstractBean>()

    for (rawLine in lines) {
        val line = rawLine.trim()
        if (line.isEmpty() || line.startsWith("#") || line.startsWith(";") || line.startsWith("//")) continue

        if (line.startsWith("[") && line.endsWith("]")) {
            val sectionName = line.substring(1, line.length - 1).trim()
            inProxySection = sectionName.equals("Proxy", ignoreCase = true)
            continue
        }

        if (inProxySection) {
            parseSurgeLine(line)?.let { beans.add(it) }
        }
    }
    return beans
}

fun parseSurgeLine(line: String): AbstractBean? {
    val equalsIdx = line.indexOf('=')
    if (equalsIdx <= 0) return null
    val tag = line.substring(0, equalsIdx).trim().removeSurrounding("\"").removeSurrounding("'")
    val right = line.substring(equalsIdx + 1).trim()
    val tokens = splitArgsRespectingQuotes(right)
    if (tokens.isEmpty()) return null

    val type = tokens[0].trim().lowercase()
    if (type == "direct") {
        return DirectBean().apply {
            this.name = tag
            initializeDefaultValues()
        }
    }

    if (tokens.size < 3) return null
    val server = tokens[1].trim().removeSurrounding("\"").removeSurrounding("'").removeSurrounding("[", "]")
    val port = tokens[2].trim().toIntOrNull() ?: 0

    val map = mutableMapOf<String, Any?>()
    map["name"] = tag
    map["type"] = type
    map["server"] = server
    map["port"] = port

    var argIndex = 3
    while (argIndex < tokens.size) {
        val token = tokens[argIndex]
        val sepIdx = token.indexOf('=').takeIf { it >= 0 } ?: token.indexOf(':')

        if (sepIdx > 0) {
            val k = token.substring(0, sepIdx).trim().lowercase()
            val v = token.substring(sepIdx + 1).trim().removeSurrounding("\"").removeSurrounding("'")

            when (k) {
                "encrypt-method", "method" -> map["cipher"] = v
                "uuid" -> map["uuid"] = v
                "password" -> {
                    if (type == "vmess" || type == "vless") map["uuid"] = v
                    else map["password"] = v
                }
                "psk" -> map["password"] = v
                "token" -> map["password"] = v
                "username" -> {
                    if (type == "vmess" || type == "vless") map["uuid"] = v
                    else map["username"] = v
                }
                "flow" -> map["flow"] = v
                "sni", "tls-host", "tls-name", "servername", "peer" -> map["sni"] = v
                "skip-cert-verify" -> map["skip-cert-verify"] = (v == "true" || v == "1" || v == "yes")
                "tls-verification" -> map["skip-cert-verify"] = (v == "false" || v == "0" || v == "no")
                "alpn" -> map["alpn"] = v
                "ws", "websocket" -> if (v == "true" || v == "1") map["network"] = "ws"
                "transport" -> map["network"] = v
                "ws-path", "path" -> {
                    @Suppress("UNCHECKED_CAST")
                    val wsOpts = (map["ws-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["ws-opts"] = it }
                    wsOpts["path"] = v
                }
                "ws-headers", "headers" -> {
                    val headersMap = mutableMapOf<String, Any?>()
                    val headerPairs = v.split("|").flatMap { it.split(",") }
                    for (pair in headerPairs) {
                        val cIdx = pair.indexOf(':')
                        if (cIdx > 0) {
                            headersMap[pair.substring(0, cIdx).trim()] = pair.substring(cIdx + 1).trim()
                        }
                    }
                    @Suppress("UNCHECKED_CAST")
                    val wsOpts = (map["ws-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["ws-opts"] = it }
                    wsOpts["headers"] = headersMap
                }
                "host" -> {
                    @Suppress("UNCHECKED_CAST")
                    val wsOpts = (map["ws-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["ws-opts"] = it }
                    @Suppress("UNCHECKED_CAST")
                    val headersMap = (wsOpts["headers"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { wsOpts["headers"] = it }
                    headersMap["Host"] = v
                }
                "h2" -> if (v == "true" || v == "1") map["network"] = "h2"
                "h2-path" -> {
                    @Suppress("UNCHECKED_CAST")
                    val h2Opts = (map["h2-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["h2-opts"] = it }
                    h2Opts["path"] = v
                }
                "h2-host" -> {
                    @Suppress("UNCHECKED_CAST")
                    val h2Opts = (map["h2-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["h2-opts"] = it }
                    h2Opts["host"] = v
                }
                "grpc-service-name", "service-name", "servicename" -> {
                    @Suppress("UNCHECKED_CAST")
                    val grpcOpts = (map["grpc-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["grpc-opts"] = it }
                    grpcOpts["grpc-service-name"] = v
                }
                "tls", "over-tls" -> if (v == "true" || v == "1") map["tls"] = true
                "reality" -> if (v == "true" || v == "1") map["tls"] = true
                "obfs" -> {
                    if (type == "snell") {
                        @Suppress("UNCHECKED_CAST")
                        val obfsOpts = (map["obfs-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["obfs-opts"] = it }
                        obfsOpts["mode"] = v
                    } else {
                        map["obfs"] = v
                        if (type == "ss" || type == "shadowsocks") {
                            map["plugin"] = "obfs"
                            @Suppress("UNCHECKED_CAST")
                            val pluginOpts = (map["plugin-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["plugin-opts"] = it }
                            pluginOpts["mode"] = v
                        }
                    }
                }
                "obfs-host" -> {
                    map["obfs-param"] = v
                    @Suppress("UNCHECKED_CAST")
                    val obfsOpts = (map["obfs-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["obfs-opts"] = it }
                    obfsOpts["host"] = v
                    @Suppress("UNCHECKED_CAST")
                    val pluginOpts = (map["plugin-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["plugin-opts"] = it }
                    pluginOpts["host"] = v
                }
                "obfs-uri" -> {
                    @Suppress("UNCHECKED_CAST")
                    val obfsOpts = (map["obfs-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["obfs-opts"] = it }
                    obfsOpts["uri"] = v
                }
                "shadow-tls-password" -> {
                    map["plugin"] = "shadow-tls"
                    @Suppress("UNCHECKED_CAST")
                    val pluginOpts = (map["plugin-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["plugin-opts"] = it }
                    pluginOpts["password"] = v
                }
                "shadow-tls-sni" -> {
                    @Suppress("UNCHECKED_CAST")
                    val pluginOpts = (map["plugin-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["plugin-opts"] = it }
                    pluginOpts["host"] = v
                }
                "shadow-tls-version" -> {
                    @Suppress("UNCHECKED_CAST")
                    val pluginOpts = (map["plugin-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["plugin-opts"] = it }
                    pluginOpts["version"] = v.toIntOrNull() ?: 2
                }
                "download-bandwidth", "down" -> map["down"] = v
                "upload-bandwidth", "up" -> map["up"] = v
                "udp-relay" -> if (v == "true" || v == "1") map["udp"] = true
                "tfo", "fast-open" -> if (v == "true" || v == "1") map["tfo"] = true
                "client-fingerprint", "fingerprint", "fp" -> map["client-fingerprint"] = v
                "version" -> map["version"] = v.toIntOrNull() ?: 0
                "congestion-controller" -> map["congestion-controller"] = v
                "udp-relay-mode" -> map["udp-relay-mode"] = v
                "public-key", "pbk" -> {
                    @Suppress("UNCHECKED_CAST")
                    val realityOpts = (map["reality-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["reality-opts"] = it }
                    realityOpts["public-key"] = v
                    map["public-key"] = v
                    map["tls"] = true
                }
                "short-id", "sid" -> {
                    @Suppress("UNCHECKED_CAST")
                    val realityOpts = (map["reality-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["reality-opts"] = it }
                    realityOpts["short-id"] = v
                    map["short-id"] = v
                }
                "packet-encoding" -> map["packet-encoding"] = v
                "ip" -> map["ip"] = v
                "private-key" -> map["private-key"] = v
                "preshared-key" -> map["preshared-key"] = v
                "mtu" -> map["mtu"] = v.toIntOrNull() ?: 0
                "reserved" -> map["reserved"] = v
                "protocol" -> map["protocol"] = v
                "protocol-param", "protocol_param" -> map["protocol-param"] = v
                "quic" -> if (v == "true" || v == "1") map["quic"] = true
            }
        } else {
            val plain = token.removeSurrounding("\"").removeSurrounding("'")
            if (type == "http" || type == "https" || type == "socks5" || type == "socks5-tls") {
                if (!map.containsKey("username")) {
                    map["username"] = plain
                } else if (!map.containsKey("password")) {
                    map["password"] = plain
                }
            } else if (type == "ss" || type == "shadowsocks") {
                if (!map.containsKey("cipher")) {
                    map["cipher"] = plain
                } else if (!map.containsKey("password")) {
                    map["password"] = plain
                }
            } else if (type == "vmess" || type == "vless") {
                if (!map.containsKey("uuid")) {
                    map["uuid"] = plain
                }
            } else if (type == "trojan") {
                if (!map.containsKey("password")) {
                    map["password"] = plain
                }
            }
        }
        argIndex++
    }

    if (type == "https" || type == "socks5-tls") {
        map["tls"] = true
    }

    return parseClashProxy(map)
}

// ==================== Quantumult X Parsers ====================

private val QX_PROXY_TYPES = setOf(
    "shadowsocks", "ss", "vmess", "vless", "trojan", "http", "socks5", "anytls"
)

fun isQuantumultXLine(line: String): Boolean {
    val equalsIdx = line.indexOf('=')
    if (equalsIdx <= 0) return false
    val left = line.substring(0, equalsIdx).trim().lowercase()
    if (left !in QX_PROXY_TYPES) return false
    val right = line.substring(equalsIdx + 1).trim()
    val firstToken = right.substringBefore(',').trim()
    return firstToken.contains(':') && firstToken.substringAfterLast(':').all { it.isDigit() }
}

fun parseQuantumultXSection(text: String): List<AbstractBean> {
    val lines = text.lines()
    var inSection = false
    val beans = mutableListOf<AbstractBean>()

    for (rawLine in lines) {
        val line = rawLine.trim()
        if (line.isEmpty() || line.startsWith("#") || line.startsWith(";") || line.startsWith("//")) continue

        if (line.startsWith("[") && line.endsWith("]")) {
            val sectionName = line.substring(1, line.length - 1).trim()
            inSection = sectionName.equals("server_local", ignoreCase = true)
            continue
        }

        if (inSection) {
            parseQuantumultXLine(line)?.let { beans.add(it) }
        }
    }
    return beans
}

fun parseQuantumultXLine(line: String): AbstractBean? {
    val equalsIdx = line.indexOf('=')
    if (equalsIdx <= 0) return null
    var type = line.substring(0, equalsIdx).trim().lowercase()
    if (type !in QX_PROXY_TYPES) return null

    val right = line.substring(equalsIdx + 1).trim()
    val tokens = splitArgsRespectingQuotes(right)
    if (tokens.isEmpty()) return null

    val addrToken = tokens[0].trim()
    val colonIdx = addrToken.lastIndexOf(':')
    if (colonIdx <= 0) return null
    val server = addrToken.substring(0, colonIdx).trim().removeSurrounding("[", "]")
    val port = addrToken.substring(colonIdx + 1).trim().toIntOrNull() ?: return null

    val map = mutableMapOf<String, Any?>()
    map["server"] = server
    map["port"] = port

    for (token in tokens.drop(1)) {
        val sepIdx = token.indexOf('=').takeIf { it >= 0 } ?: token.indexOf(':')
        if (sepIdx <= 0) {
            val plain = token.removeSurrounding("\"").removeSurrounding("'")
            if (type == "vmess" || type == "vless") {
                if (!map.containsKey("uuid")) map["uuid"] = plain
            } else if (type == "trojan") {
                if (!map.containsKey("password")) map["password"] = plain
            }
            continue
        }

        val k = token.substring(0, sepIdx).trim().lowercase()
        val v = token.substring(sepIdx + 1).trim().removeSurrounding("\"").removeSurrounding("'")

        when (k) {
            "tag" -> map["name"] = v
            "uuid" -> map["uuid"] = v
            "method" -> map["cipher"] = v
            "password" -> {
                if (type == "vmess" || type == "vless") map["uuid"] = v
                else map["password"] = v
            }
            "flow" -> map["flow"] = v
            "username" -> map["username"] = v
            "ssr-protocol" -> {
                type = "ssr"
                map["protocol"] = v
            }
            "ssr-protocol-param" -> map["protocol-param"] = v
            "obfs" -> {
                when (v.lowercase()) {
                    "ws", "websocket" -> map["network"] = "ws"
                    "wss" -> {
                        map["network"] = "ws"
                        map["tls"] = true
                    }
                    "http" -> {
                        if (type == "ss" || type == "shadowsocks" || type == "ssr") {
                            map["obfs"] = "http"
                            map["plugin"] = "obfs"
                            @Suppress("UNCHECKED_CAST")
                            val pluginOpts = (map["plugin-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["plugin-opts"] = it }
                            pluginOpts["mode"] = "http"
                        } else {
                            map["network"] = "http"
                        }
                    }
                    "over-tls", "tls" -> {
                        if (type == "ss" || type == "shadowsocks" || type == "ssr") {
                            map["obfs"] = "tls"
                            map["plugin"] = "obfs"
                            @Suppress("UNCHECKED_CAST")
                            val pluginOpts = (map["plugin-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["plugin-opts"] = it }
                            pluginOpts["mode"] = "tls"
                        } else {
                            map["tls"] = true
                        }
                    }
                    else -> map["obfs"] = v
                }
            }
            "obfs-host" -> {
                map["obfs-param"] = v
                @Suppress("UNCHECKED_CAST")
                val wsOpts = (map["ws-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["ws-opts"] = it }
                @Suppress("UNCHECKED_CAST")
                val wsHeaders = (wsOpts["headers"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { wsOpts["headers"] = it }
                wsHeaders["Host"] = v
                @Suppress("UNCHECKED_CAST")
                val pluginOpts = (map["plugin-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["plugin-opts"] = it }
                pluginOpts["host"] = v
            }
            "obfs-uri" -> {
                @Suppress("UNCHECKED_CAST")
                val wsOpts = (map["ws-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["ws-opts"] = it }
                wsOpts["path"] = v
            }
            "over-tls", "tls" -> if (v == "true" || v == "1") map["tls"] = true
            "tls-host" -> map["sni"] = v
            "tls-verification" -> if (v == "false" || v == "0" || v == "no") map["skip-cert-verify"] = true
            "tls-alpn" -> map["alpn"] = v
            "tls-fingerprint", "fp" -> map["client-fingerprint"] = v
            "udp-relay" -> if (v == "true" || v == "1") map["udp"] = true
            "fast-open" -> if (v == "true" || v == "1") map["tfo"] = true
            "reality-base64-pubkey", "public-key", "pbk" -> {
                @Suppress("UNCHECKED_CAST")
                val realityOpts = (map["reality-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["reality-opts"] = it }
                realityOpts["public-key"] = v
                map["public-key"] = v
                map["tls"] = true
            }
            "reality-hex-shortid", "short-id", "sid" -> {
                @Suppress("UNCHECKED_CAST")
                val realityOpts = (map["reality-opts"] as? MutableMap<String, Any?>) ?: mutableMapOf<String, Any?>().also { map["reality-opts"] = it }
                realityOpts["short-id"] = v
                map["short-id"] = v
            }
        }
    }

    map["type"] = type
    if (!map.containsKey("name")) {
        map["name"] = "$type-$server:$port"
    }

    return parseClashProxy(map)
}

private fun splitArgsRespectingQuotes(input: String, delimiter: Char = ','): List<String> {
    val results = mutableListOf<String>()
    var inSingleQuote = false
    var inDoubleQuote = false
    var escape = false
    var bracketDepth = 0
    var braceDepth = 0
    var parenDepth = 0
    val current = StringBuilder()

    for (i in input.indices) {
        val c = input[i]
        if (escape) {
            current.append(c)
            escape = false
            continue
        }
        if (c == '\\' && inDoubleQuote) {
            escape = true
            current.append(c)
            continue
        }
        if (c == '\'' && !inDoubleQuote) {
            inSingleQuote = !inSingleQuote
            current.append(c)
            continue
        }
        if (c == '"' && !inSingleQuote) {
            inDoubleQuote = !inDoubleQuote
            current.append(c)
            continue
        }
        if (!inSingleQuote && !inDoubleQuote) {
            when (c) {
                '[' -> bracketDepth++
                ']' -> if (bracketDepth > 0) bracketDepth--
                '{' -> braceDepth++
                '}' -> if (braceDepth > 0) braceDepth--
                '(' -> parenDepth++
                ')' -> if (parenDepth > 0) parenDepth--
                delimiter -> {
                    if (bracketDepth == 0 && braceDepth == 0 && parenDepth == 0) {
                        results.add(current.toString().trim())
                        current.clear()
                        continue
                    }
                }
            }
        }
        current.append(c)
    }
    if (current.isNotBlank()) {
        results.add(current.toString().trim())
    }
    return results
}

private fun Map<String, Any?>.getStr(key: String): String? =
    this[key]?.toString()?.blankAsNull()

private fun Map<String, Any?>.getInt(key: String): Int? =
    when (val v = this[key]) {
        is Number -> v.toInt()
        is String -> v.toIntOrNull()
        else -> null
    }

private fun Map<String, Any?>.getBool(key: String): Boolean? =
    when (val v = this[key]) {
        is Boolean -> v
        is String -> v.lowercase().let { it == "true" || it == "1" || it == "yes" }
        is Number -> v.toInt() != 0
        else -> null
    }

@Suppress("UNCHECKED_CAST")
private fun Map<String, Any?>.getMap(key: String): Map<String, Any?>? =
    this[key] as? Map<String, Any?>

private fun Map<String, Any?>.getStrList(key: String): List<String>? =
    when (val v = this[key]) {
        is List<*> -> v.mapNotNull { it?.toString()?.blankAsNull() }
        is String -> v.split(",").mapNotNull { it.trim().blankAsNull() }
        else -> null
    }

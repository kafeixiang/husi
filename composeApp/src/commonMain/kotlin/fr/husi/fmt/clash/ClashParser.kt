package fr.husi.fmt.clash

import fr.husi.fmt.AbstractBean
import fr.husi.fmt.anytls.AnyTLSBean
import fr.husi.fmt.http.HttpBean
import fr.husi.fmt.hysteria.HysteriaBean
import fr.husi.fmt.juicity.JuicityBean
import fr.husi.fmt.mieru.MieruBean
import fr.husi.fmt.shadowquic.ShadowQUICBean
import fr.husi.fmt.shadowsocks.ShadowsocksBean
import fr.husi.fmt.shadowsocks.pluginToLocal
import fr.husi.fmt.shadowtls.ShadowTLSBean
import fr.husi.fmt.snell.SnellBean
import fr.husi.fmt.socks.SOCKSBean
import fr.husi.fmt.ssr.SSRBean
import fr.husi.fmt.trojan.TrojanBean
import fr.husi.fmt.tuic.TuicBean
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
                this.protocolParam = map.getStr("protocol-param") ?: map.getStr("protocolparam") ?: ""
                this.obfs = map.getStr("obfs") ?: ""
                this.obfsParam = map.getStr("obfs-param") ?: map.getStr("obfsparam") ?: ""
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
            }
        }

        "vless" -> {
            VLESSBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.uuid = map.getStr("uuid") ?: ""
                this.flow = map.getStr("flow") ?: ""

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

                val realityOpts = map.getMap("reality-opts")
                if (realityOpts != null) {
                    this.realityPublicKey = realityOpts.getStr("public-key") ?: ""
                    this.realityShortID = realityOpts.getStr("short-id") ?: ""
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
            }
        }

        "hysteria", "hysteria1" -> {
            HysteriaBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPorts = map.getStr("ports") ?: (if (port > 0) port.toString() else "443")
                this.protocolVersion = HysteriaBean.PROTOCOL_VERSION_1

                val auth = map.getStr("auth") ?: map.getStr("auth_str") ?: map.getStr("auth-str") ?: ""
                if (auth.isNotBlank()) {
                    this.authPayload = auth
                    this.authPayloadType = HysteriaBean.TYPE_STRING
                }

                this.sni = map.getStr("sni") ?: map.getStr("servername") ?: ""
                this.allowInsecure = map.getBool("skip-cert-verify") == true
                this.obfsPassword = map.getStr("obfs") ?: map.getStr("obfs-param") ?: ""

                val alpnList = map["alpn"] as? List<*>
                if (alpnList != null) {
                    this.alpn = alpnList.joinToString(",") { it.toString() }
                }
            }
        }

        "hysteria2", "hy2" -> {
            HysteriaBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPorts = map.getStr("ports") ?: (if (port > 0) port.toString() else "443")
                this.protocolVersion = HysteriaBean.PROTOCOL_VERSION_2

                val password = map.getStr("password") ?: map.getStr("auth") ?: ""
                if (password.isNotBlank()) {
                    this.authPayload = password
                    this.authPayloadType = HysteriaBean.TYPE_STRING
                }

                this.sni = map.getStr("sni") ?: map.getStr("servername") ?: ""
                this.allowInsecure = map.getBool("skip-cert-verify") == true || map.getBool("insecure") == true

                val obfsType = map.getStr("obfs") ?: ""
                val obfsPassword = map.getStr("obfs-password") ?: ""
                if (obfsType.isNotBlank()) {
                    this.obfsType = obfsType
                } else if (obfsPassword.isNotBlank()) {
                    this.obfsType = HysteriaBean.OBFS_TYPE_SALAMANDER
                }
                this.obfsPassword = obfsPassword
            }
        }

        "tuic" -> {
            TuicBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.uuid = map.getStr("uuid") ?: ""
                this.token = map.getStr("password") ?: map.getStr("token") ?: ""
                this.sni = map.getStr("sni") ?: map.getStr("servername") ?: ""
                this.congestionController = map.getStr("congestion-controller") ?: map.getStr("congestion_control") ?: "bbr"
                this.udpRelayMode = map.getStr("udp-relay-mode") ?: map.getStr("udp_relay_mode") ?: "native"
                this.allowInsecure = map.getBool("skip-cert-verify") == true

                val alpnList = map["alpn"] as? List<*>
                if (alpnList != null) {
                    this.alpn = alpnList.joinToString(",") { it.toString() }
                }
            }
        }

        "juicity" -> {
            JuicityBean().apply {
                this.name = name
                this.serverAddress = server
                this.serverPort = if (port > 0) port else defaultPort
                this.uuid = map.getStr("uuid") ?: ""
                this.password = map.getStr("password") ?: ""
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

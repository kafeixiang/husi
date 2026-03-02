package fr.husi.fmt.ssr

import fr.husi.fmt.parseBoxOutbound
import fr.husi.ktx.JSONMap
import fr.husi.ktx.b64DecodeToString
import fr.husi.ktx.b64EncodeUrlSafe
import fr.husi.ktx.blankAsNull
import fr.husi.ktx.getStr

val supportedShadowsocksRMethod = arrayOf(
    "rc4-md5",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "bf-cfb",
    "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
    "salsa20", "chacha20", "chacha20-ietf", "xchacha20",
    "none", "table"
)

val supportedShadowsocksRProtocol = arrayOf(
    "origin", "auth_sha1_v4", "auth_aes128_sha1", "auth_aes128_md5", "auth_chain_a", "auth_chain_b"
)

val supportedShadowsocksRObfs = arrayOf(
    "plain", "http_simple", "http_post", "tls1.2_ticket_auth", "random_head"
)

fun parseShadowsocksR(url: String): ShadowsocksRBean {
    // https://github.com/shadowsocksrr/shadowsocks-rss/wiki/SSR-QRcode-scheme
    val b64 = url.substringAfter("ssr://")
    val decoded = b64.b64DecodeToString()
    val params = decoded.split(":")
    if (params.size < 6) error("invalid url")

    val bean = ShadowsocksRBean().apply {
        serverAddress = params.subList(0, params.size - 5).joinToString(":")
        serverPort = params[params.size - 5].toIntOrNull() ?: error("invalid port")
        protocol = params[params.size - 4].takeIf { it in supportedShadowsocksRProtocol } ?: "origin"
        method = params[params.size - 3].takeIf { it in supportedShadowsocksRMethod } ?: "aes-256-cfb"
        obfs = when (val it = params[params.size - 2]) {
            "tls1.2_ticket_fastauth" -> "tls1.2_ticket_auth"
            else -> it.takeIf { it in supportedShadowsocksRObfs } ?: "plain"
        }
        val lastPart = params[params.size - 1]
        val passwordB64 = lastPart.substringBefore("/")
        password = passwordB64.b64DecodeToString()
    }

    val queryPart = params[params.size - 1].substringAfter("/", "")
    if (queryPart.isNotBlank()) {
        val pairs = queryPart.removePrefix("?").split("&")
        for (pair in pairs) {
            val keyValue = pair.split("=", limit = 2)
            if (keyValue.size != 2) continue
            val key = keyValue[0].lowercase()
            val value = keyValue[1]
            if (value.isBlank()) continue
            
            runCatching {
                when (key) {
                    "obfsparam" -> bean.obfsParam = value.b64DecodeToString()
                    "protoparam" -> bean.protocolParam = value.b64DecodeToString()
                    "remarks" -> bean.name = value.b64DecodeToString()
                }
            }
        }
    }

    return bean
}

fun ShadowsocksRBean.toUri(): String {
    val passwordB64 = password.b64EncodeUrlSafe()
    val obfsParamB64 = obfsParam.b64EncodeUrlSafe()
    val protoParamB64 = protocolParam.b64EncodeUrlSafe()
    val remarksB64 = (name ?: "").b64EncodeUrlSafe()
    
    val mainPart = "$serverAddress:$serverPort:$protocol:$method:$obfs:$passwordB64"
    val queryPart = "/?obfsparam=$obfsParamB64&protoparam=$protoParamB64&remarks=$remarksB64"
    
    return "ssr://" + (mainPart + queryPart).b64EncodeUrlSafe()
}

fun buildSingBoxOutboundShadowsocksRBean(bean: ShadowsocksRBean): MutableMap<String, Any?> {
    return mutableMapOf(
        "type" to "shadowsocksr",
        "server" to bean.serverAddress,
        "server_port" to bean.serverPort,
        "method" to bean.method,
        "password" to bean.password,
        "obfs" to bean.obfs,
        "obfs_param" to bean.obfsParam.blankAsNull(),
        "protocol" to bean.protocol,
        "protocol_param" to bean.protocolParam.blankAsNull(),
        "network" to bean.network,
    )
}

fun parseShadowsocksROutbound(json: JSONMap): ShadowsocksRBean = ShadowsocksRBean().apply {
    parseBoxOutbound(json) { key, value ->
        when (key) {
            "password" -> password = value.toString()
            "method" -> method = value.toString()
            "obfs" -> obfs = value.toString()
            "obfs_param" -> obfsParam = value.toString()
            "protocol" -> protocol = value.toString()
            "protocol_param" -> protocolParam = value.toString()
            "network" -> network = value.toString()
        }
    }
}

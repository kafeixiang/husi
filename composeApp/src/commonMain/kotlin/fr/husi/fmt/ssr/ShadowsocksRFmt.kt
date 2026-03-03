package fr.husi.fmt.ssr

import fr.husi.fmt.parseBoxOutbound
import fr.husi.ktx.JSONMap
import fr.husi.ktx.b64Decode
import fr.husi.ktx.b64DecodeToString
import fr.husi.ktx.b64EncodeUrlSafe
import fr.husi.ktx.blankAsNull
import fr.husi.ktx.getStr
import kotlin.io.encoding.Base64

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

/**
 * SSR 专用的 Base64 解码。
 * SSR 链接内部的参数解码逻辑比较混乱，通常需要尝试多种方式。
 */
private fun String.ssrParamDecode(): String {
    if (this.isBlank()) return ""
    // 1. 尝试 URL Safe 解码（不带手动替换）
    try {
        return Base64.UrlSafe.decode(this).decodeToString()
    } catch (_: Exception) {}
    
    // 2. 尝试标准解码（不带手动替换）
    try {
        return Base64.Default.decode(this).decodeToString()
    } catch (_: Exception) {}

    // 3. 尝试带手动替换的解码 (ktx 版本)
    try {
        val decoded = this.b64DecodeToString()
        // 检查解码结果是否包含不可见字符，如果是，可能不应该解码
        if (decoded.any { it.code < 32 && it != '\n' && it != '\r' && it != '\t' }) {
             // 含有过多不可见字符，怀疑是解码错误
        } else {
            return decoded
        }
    } catch (_: Exception) {}

    // 4. 最后回退到原始字符串
    return this
}

fun parseShadowsocksR(url: String): ShadowsocksRBean {
    // ssr://host:port:protocol:method:obfs:base64pass/?obfsparam=base64&protoparam=base64&remarks=base64
    val b64 = url.substringAfter("ssr://")
    val decoded = b64.b64DecodeToString()
    
    val queryIndex = decoded.lastIndexOf("/?")
    val mainPart = if (queryIndex != -1) decoded.substring(0, queryIndex) else decoded
    val queryPart = if (queryIndex != -1) decoded.substring(queryIndex + 2) else ""

    val params = mainPart.split(":")
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
        // 密码通常是必须解码的
        password = params[params.size - 1].ssrParamDecode()
    }

    if (queryPart.isNotBlank()) {
        val pairs = queryPart.split("&")
        for (pair in pairs) {
            val keyValue = pair.split("=", limit = 2)
            if (keyValue.size != 2) continue
            val key = keyValue[0].lowercase()
            val value = keyValue[1]
            if (value.isBlank()) continue
            
            when (key) {
                "obfsparam" -> bean.obfsParam = value.ssrParamDecode()
                "protoparam" -> {
                    // 特殊处理 protoparam: 如果包含冒号且冒号前是数字，通常是明文 UID:KEY，不要解码
                    if (value.contains(":") && value.substringBefore(":").all { it.isDigit() }) {
                        bean.protocolParam = value
                    } else {
                        bean.protocolParam = value.ssrParamDecode()
                    }
                }
                "remarks" -> bean.name = value.ssrParamDecode()
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
        "type" to "ssr",
        "server" to bean.serverAddress,
        "server_port" to bean.serverPort,
        "method" to bean.method,
        "password" to bean.password,
        "obfs" to bean.obfs,
        "obfs_param" to bean.obfsParam.blankAsNull(),
        "protocol" to bean.protocol,
        "protocol_param" to bean.protocolParam.blankAsNull(),
        "network" to bean.network.split(",").filter { it.isNotBlank() },
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

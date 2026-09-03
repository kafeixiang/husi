package fr.husi.fmt.ssr

import fr.husi.fmt.SingBoxOptions
import fr.husi.fmt.parseBoxOutbound
import fr.husi.ktx.JSONMap
import fr.husi.ktx.b64Decode
import fr.husi.ktx.b64EncodeUrlSafe
import fr.husi.ktx.getStr

private fun String.ssrB64Decode(): String {
    if (this.isBlank()) return ""
    var str = this.replace("-", "+").replace("_", "/")
    val remainder = str.length % 4
    if (remainder > 0) {
        str += "=".repeat(4 - remainder)
    }
    return try {
        str.b64Decode().decodeToString()
    } catch (e: Exception) {
        ""
    }
}


fun parseSSR(rawUrl: String): SSRBean {
    val b64 = rawUrl.removePrefix("ssr://").substringBefore("#")
    val decoded = b64.ssrB64Decode()
    if (decoded.isBlank()) throw IllegalArgumentException("Invalid SSR link: Base64 decode failed")
    
    val queryIndex = decoded.indexOf("/?")
    val mainPart = if (queryIndex >= 0) decoded.substring(0, queryIndex) else decoded
    val queryPart = if (queryIndex >= 0) decoded.substring(queryIndex + 2) else ""
    
    val parts = mainPart.split(":")
    if (parts.size < 6) throw IllegalArgumentException("Invalid SSR link: missing parts")
    
    return SSRBean().apply {
        serverAddress = parts[0]
        serverPort = parts[1].toIntOrNull() ?: 8388
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        password = parts[5].ssrB64Decode()
        
        if (queryPart.isNotBlank()) {
            val params = queryPart.split("&")
            params.forEach { param ->
                val key = param.substringBefore("=")
                val value = param.substringAfter("=").ssrB64Decode()
                when (key) {
                    "obfsparam" -> obfsParam = value
                    "protoparam" -> protocolParam = value
                    "remarks" -> name = value
                }
            }
        }
    }
}

fun SSRBean.toUri(): String {
    val b64Pass = password.encodeToByteArray().b64EncodeUrlSafe().trimEnd('=')
    val mainPart = "$serverAddress:$serverPort:$protocol:$method:$obfs:$b64Pass"
    
    val queryParams = mutableListOf<String>()
    if (obfsParam.isNotBlank()) queryParams.add("obfsparam=${obfsParam.encodeToByteArray().b64EncodeUrlSafe().trimEnd('=')}")
    if (protocolParam.isNotBlank()) queryParams.add("protoparam=${protocolParam.encodeToByteArray().b64EncodeUrlSafe().trimEnd('=')}")
    if (name.isNotBlank()) queryParams.add("remarks=${name.encodeToByteArray().b64EncodeUrlSafe().trimEnd('=')}")
    
    val url = if (queryParams.isEmpty()) mainPart else "$mainPart/?${queryParams.joinToString("&")}"
    return "ssr://${url.encodeToByteArray().b64EncodeUrlSafe().trimEnd('=')}"
}

fun JSONMap.parseSSR(): SSRBean {
    return SSRBean().apply {
        serverAddress = getStr("server").orEmpty()
        serverPort = (this@parseSSR["server_port"] as? Number)?.toInt() ?: defaultPort
        password = getStr("password").orEmpty()
        method = getStr("method").orEmpty()
        protocol = getStr("protocol").orEmpty()
        protocolParam = getStr("protocol_param").orEmpty()
        obfs = getStr("obfs").orEmpty()
        obfsParam = getStr("obfs_param").orEmpty()
        name = getStr("tag").orEmpty()
    }
}

fun buildSingBoxOutboundSSRBean(bean: SSRBean): SingBoxOptions.Outbound_ShadowsocksROptions {
    return SingBoxOptions.Outbound_ShadowsocksROptions().apply {
        type = SingBoxOptions.TYPE_SSR
        server = bean.serverAddress
        server_port = bean.serverPort
        method = bean.method
        password = bean.password
        protocol = bean.protocol
        protocol_param = bean.protocolParam
        obfs = bean.obfs
        obfs_param = bean.obfsParam
        network = bean.network().split(",").toMutableList()
    }
}

fun parseSSROutbound(json: JSONMap): SSRBean = SSRBean().apply {
    parseBoxOutbound(json) { key, value ->
        when (key) {
            "password" -> password = value.toString()
            "method" -> method = value.toString()
            "protocol" -> protocol = value.toString()
            "protocol_param" -> protocolParam = value.toString()
            "obfs" -> obfs = value.toString()
            "obfs_param" -> obfsParam = value.toString()
        }
    }
}

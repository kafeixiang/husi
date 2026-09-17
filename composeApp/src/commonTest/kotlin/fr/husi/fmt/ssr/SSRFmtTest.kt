package fr.husi.fmt.ssr

import fr.husi.ktx.JSONMap
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class SSRFmtTest {

    @Test
    fun `parseSSR should parse standard ssr url`() {
        val source = SSRBean().apply {
            serverAddress = "127.0.0.1"
            serverPort = 8388
            protocol = "auth_chain_a"
            method = "aes-256-cfb"
            obfs = "tls1.2_ticket_auth"
            password = "mypassword"
            name = "TestNode"
            obfsParam = "cloudflare.com"
            protocolParam = "12:secret"
        }

        val url = source.toUri()
        val bean = parseSSR(url)

        assertEquals("127.0.0.1", bean.serverAddress)
        assertEquals(8388, bean.serverPort)
        assertEquals("auth_chain_a", bean.protocol)
        assertEquals("aes-256-cfb", bean.method)
        assertEquals("tls1.2_ticket_auth", bean.obfs)
        assertEquals("mypassword", bean.password)
        assertEquals("TestNode", bean.name)
        assertEquals("cloudflare.com", bean.obfsParam)
        assertEquals("12:secret", bean.protocolParam)
    }

    @Test
    fun `parseSSR should handle IPv6 address in url`() {
        val source = SSRBean().apply {
            serverAddress = "2001:db8::1"
            serverPort = 8388
            protocol = "origin"
            method = "aes-128-ctr"
            obfs = "plain"
            password = "pass"
            name = "IPv6Node"
        }

        val url = source.toUri()
        val bean = parseSSR(url)

        assertEquals("2001:db8::1", bean.serverAddress)
        assertEquals(8388, bean.serverPort)
        assertEquals("origin", bean.protocol)
        assertEquals("aes-128-ctr", bean.method)
        assertEquals("plain", bean.obfs)
        assertEquals("pass", bean.password)
        assertEquals("IPv6Node", bean.name)
    }

    @Test
    fun `parseSSR should fallback to unencoded plaintext for remarks and query params`() {
        // Construct an SSR main part with unencoded remarks in query
        val mainPart = "10.0.0.1:8388:origin:aes-256-cfb:plain:cGFzc3dvcmQ" // password = "password"
        val rawUrl = "ssr://${mainPart}/?remarks=MyPlaintextNode&obfsparam=bing.com&protoparam=12:abc"

        val bean = parseSSR(rawUrl)

        assertEquals("10.0.0.1", bean.serverAddress)
        assertEquals(8388, bean.serverPort)
        assertEquals("password", bean.password)
        assertEquals("MyPlaintextNode", bean.name)
        assertEquals("bing.com", bean.obfsParam)
        assertEquals("12:abc", bean.protocolParam)
    }

    @Test
    fun `buildSingBoxOutboundSSRBean should map all fields correctly`() = runTest {
        val bean = SSRBean().apply {
            serverAddress = "example.com"
            serverPort = 8388
            method = "chacha20-ietf"
            password = "secretpassword"
            protocol = "auth_sha1_v4"
            protocolParam = "10:key"
            obfs = "http_simple"
            obfsParam = "example.com"
        }

        val outbound = buildSingBoxOutboundSSRBean(bean)

        assertEquals("ssr", outbound.type)
        assertEquals("example.com", outbound.server)
        assertEquals(8388, outbound.server_port)
        assertEquals("chacha20-ietf", outbound.method)
        assertEquals("secretpassword", outbound.password)
        assertEquals("auth_sha1_v4", outbound.protocol)
        assertEquals("10:key", outbound.protocol_param)
        assertEquals("http_simple", outbound.obfs)
        assertEquals("example.com", outbound.obfs_param)
        assertEquals(listOf("tcp", "udp"), outbound.network as List<String>?)
    }

    @Test
    fun `parseSSROutbound should map json outbound to SSRBean`() {
        val json: JSONMap = mutableMapOf(
            "tag" to "ssr-outbound",
            "server" to "192.168.1.1",
            "server_port" to 8388L,
            "method" to "aes-256-cfb",
            "password" to "pass123",
            "protocol" to "auth_chain_b",
            "protocol_param" to "param1",
            "obfs" to "tls1.2_ticket_fastauth",
            "obfs_param" to "param2",
        )

        val bean = parseSSROutbound(json)

        assertEquals("ssr-outbound", bean.name)
        assertEquals("192.168.1.1", bean.serverAddress)
        assertEquals(8388, bean.serverPort)
        assertEquals("aes-256-cfb", bean.method)
        assertEquals("pass123", bean.password)
        assertEquals("auth_chain_b", bean.protocol)
        assertEquals("param1", bean.protocolParam)
        assertEquals("tls1.2_ticket_fastauth", bean.obfs)
        assertEquals("param2", bean.obfsParam)
    }
}

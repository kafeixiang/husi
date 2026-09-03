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
        assertEquals(true, bean.udp)
    }

    @Test
    fun `buildSingBoxOutboundSSRBean should respect udp false`() = runTest {
        val bean = SSRBean().apply {
            serverAddress = "example.com"
            serverPort = 8388
            method = "aes-256-cfb"
            password = "pass"
            udp = false
        }

        val outbound = buildSingBoxOutboundSSRBean(bean)
        assertEquals(listOf("tcp"), outbound.network as List<String>?)
    }

    @Test
    fun `parseSSROutbound should parse network list with tcp only`() {
        val json: JSONMap = mutableMapOf(
            "tag" to "ssr-tcp-only",
            "server" to "127.0.0.1",
            "server_port" to 8388L,
            "method" to "aes-256-cfb",
            "password" to "pass",
            "network" to listOf("tcp"),
        )

        val bean = parseSSROutbound(json)
        assertEquals(false, bean.udp)
        assertEquals("tcp", bean.network())
    }

    @Test
    fun `SSRBean should clone and applyFeatureSettings udp properly`() {
        val bean = SSRBean().apply {
            serverAddress = "127.0.0.1"
            serverPort = 8388
            udp = false
        }

        val cloned = bean.clone()
        assertEquals(false, cloned.udp)
        assertEquals("tcp", cloned.network())

        val other = SSRBean().apply { udp = true }
        bean.applyFeatureSettings(other)
        assertEquals(false, other.udp)
    }

    @Test
    fun `parseSSR should parse udp query parameter`() {
        val beanWithUdpFalse = SSRBean().apply {
            serverAddress = "127.0.0.1"
            serverPort = 8388
            protocol = "origin"
            method = "aes-256-cfb"
            obfs = "plain"
            password = "pass"
            udp = false
        }
        val url = beanWithUdpFalse.toUri()
        val parsed = parseSSR(url)
        assertEquals(false, parsed.udp)

        // Test udp=true and udp=1
        val parsedTrue = parseSSR("ssr://MTAuMC4wLjE6ODM4ODpvcmlnaW46YWVzLTI1Ni1jZmI6cGxhaW46Y0dGemMzZHZjbVEvP3VkcD10cnVl")
        assertEquals(true, parsedTrue.udp)

        val parsed1 = parseSSR("ssr://MTAuMC4wLjE6ODM4ODpvcmlnaW46YWVzLTI1Ni1jZmI6cGxhaW46Y0dGemMzZHZjbVEvP3VkcD0x")
        assertEquals(true, parsed1.udp)

        val parsedFalse = parseSSR("ssr://MTAuMC4wLjE6ODM4ODpvcmlnaW46YWVzLTI1Ni1jZmI6cGxhaW46Y0dGemMzZHZjbVEvP3VkcD1mYWxzZQ")
        assertEquals(false, parsedFalse.udp)
    }

    @Test
    fun `parseSSR should support shadowsocksr scheme and parameter aliases`() {
        val rawUrl = "shadowsocksr://MTAuMC4wLjE6ODM4ODpvcmlnaW46YWVzLTI1Ni1jZmI6cGxhaW46Y0dGemMzZHZjbVEvP29iZnMtaG9zdD1leGFtcGxlLmNvbSZwcm90b2NvbC1wYXJhbT0xMjM6YWJjJnJlbWFya3M9QWxpYXNOb2Rl"
        val parsed = parseSSR(rawUrl)
        assertEquals("10.0.0.1", parsed.serverAddress)
        assertEquals(8388, parsed.serverPort)
        assertEquals("example.com", parsed.obfsParam)
        assertEquals("123:abc", parsed.protocolParam)
        assertEquals("AliasNode", parsed.name)
    }

    @Test
    fun `toUri should bracket IPv6 address`() {
        val bean = SSRBean().apply {
            serverAddress = "2001:db8::1"
            serverPort = 8388
            protocol = "origin"
            method = "aes-128-ctr"
            obfs = "plain"
            password = "pass"
        }
        val uri = bean.toUri()
        val parsed = parseSSR(uri)
        assertEquals("2001:db8::1", parsed.serverAddress)
    }
}

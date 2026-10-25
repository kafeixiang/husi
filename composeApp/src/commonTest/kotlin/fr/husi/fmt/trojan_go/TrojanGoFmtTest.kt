package fr.husi.fmt.trojan_go

import fr.husi.database.ProxyEntity
import fr.husi.fmt.BeanConverters
import fr.husi.fmt.buildSingBoxOutbound
import fr.husi.fmt.clash.parseClashProxy
import fr.husi.fmt.parseOutbound
import fr.husi.ktx.kxs
import fr.husi.ktx.parseProxies
import fr.husi.ktx.toJsonMapKxs
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class TrojanGoFmtTest {

    @Test
    fun `parseTrojanGo should parse basic trojan-go url`() {
        val link = "trojan-go://secret123@example.com:443/?sni=my.sni.com#MyNode"
        val bean = parseTrojanGo(link)

        assertEquals("example.com", bean.serverAddress)
        assertEquals(443, bean.serverPort)
        assertEquals("secret123", bean.password)
        assertEquals("my.sni.com", bean.sni)
        assertEquals("original", bean.type)
        assertEquals("none", bean.encryption)
        assertFalse(bean.mux)
        assertFalse(bean.allowInsecure)
        assertEquals("MyNode", bean.name)
    }

    @Test
    fun `parseTrojanGo should parse websocket with host and path`() {
        val link = "trojan-go://secret123@1.2.3.4:8443/?type=ws&host=cdn.cloudflare.com&path=%2Ftrojan-ws#WSNode"
        val bean = parseTrojanGo(link)

        assertEquals("1.2.3.4", bean.serverAddress)
        assertEquals(8443, bean.serverPort)
        assertEquals("secret123", bean.password)
        assertEquals("ws", bean.type)
        assertEquals("cdn.cloudflare.com", bean.host)
        assertEquals("/trojan-ws", bean.path)
        assertEquals("WSNode", bean.name)
    }

    @Test
    fun `parseTrojanGo should parse shadowsocks secondary encryption`() {
        val link = "trojan-go://trojanpass@example.com:443/?encryption=ss%3Baes-256-gcm%3Asspass123#SSEncNode"
        val bean = parseTrojanGo(link)

        assertEquals("example.com", bean.serverAddress)
        assertEquals(443, bean.serverPort)
        assertEquals("trojanpass", bean.password)
        assertTrue(bean.encryption.startsWith("ss;"))
        assertEquals("aes-256-gcm", bean.ssMethod)
        assertEquals("sspass123", bean.ssPassword)
        assertEquals("SSEncNode", bean.name)
    }

    @Test
    fun `parseTrojanGo should parse mux and allowInsecure`() {
        val link = "trojan-go://pass@example.com:443/?mux=true&concurrency=16&allowInsecure=true#MuxNode"
        val bean = parseTrojanGo(link)

        assertEquals("example.com", bean.serverAddress)
        assertEquals("pass", bean.password)
        assertTrue(bean.mux)
        assertEquals(16, bean.muxConcurrency)
        assertTrue(bean.allowInsecure)
        assertEquals("MuxNode", bean.name)
    }

    @Test
    fun `toUri and parseTrojanGo should round trip with all features`() {
        val original = TrojanGoBean().apply {
            serverAddress = "trojan.test.org"
            serverPort = 10443
            password = "trojan_strong_password"
            sni = "sni.test.org"
            type = "ws"
            host = "ws.test.org"
            path = "/trojanpath"
            encryption = "ss;chacha20-ietf-poly1305:my_chacha_key"
            ssMethod = "chacha20-ietf-poly1305"
            ssPassword = "my_chacha_key"
            mux = true
            muxConcurrency = 12
            allowInsecure = true
            name = "AllFeatures"
        }

        val uri = original.toUri()
        val parsed = parseTrojanGo(uri)

        assertEquals(original.serverAddress, parsed.serverAddress)
        assertEquals(original.serverPort, parsed.serverPort)
        assertEquals(original.password, parsed.password)
        assertEquals(original.sni, parsed.sni)
        assertEquals(original.type, parsed.type)
        assertEquals(original.host, parsed.host)
        assertEquals(original.path, parsed.path)
        assertEquals(original.ssMethod, parsed.ssMethod)
        assertEquals(original.ssPassword, parsed.ssPassword)
        assertEquals(original.mux, parsed.mux)
        assertEquals(original.muxConcurrency, parsed.muxConcurrency)
        assertEquals(original.allowInsecure, parsed.allowInsecure)
        assertEquals(original.name, parsed.name)
    }

    @Test
    fun `buildSingBoxOutboundTrojanGoBean should construct full outbound options`() {
        val bean = TrojanGoBean().apply {
            serverAddress = "example.com"
            serverPort = 443
            password = "password"
            sni = "sni.example.com"
            type = "ws"
            host = "ws.example.com"
            path = "/ws"
            encryption = "ss;aes-128-gcm:sspass"
            ssMethod = "aes-128-gcm"
            ssPassword = "sspass"
            mux = true
            muxConcurrency = 8
            allowInsecure = true
        }

        val outbound = buildSingBoxOutboundTrojanGoBean(bean)

        assertEquals("trojan-go", outbound.type)
        assertEquals("example.com", outbound.server)
        assertEquals(443, outbound.server_port)
        assertEquals("password", outbound.password)
        assertNotNull(outbound.tls)
        assertEquals("sni.example.com", outbound.tls?.server_name)
        assertEquals(true, outbound.tls?.insecure)
        assertNotNull(outbound.transport)
        assertNotNull(outbound.shadowsocks)
        assertEquals(true, outbound.shadowsocks?.enabled)
        assertEquals("aes-128-gcm", outbound.shadowsocks?.method)
        assertEquals("sspass", outbound.shadowsocks?.password)
        assertNotNull(outbound.mux)
        assertEquals(true, outbound.mux?.enabled)
        assertEquals(8, outbound.mux?.concurrency)
    }

    @Test
    fun `BeanConverters and ProxyEntity should serialize and deserialize TrojanGoBean`() {
        val bean = TrojanGoBean().apply {
            serverAddress = "10.0.0.1"
            serverPort = 443
            password = "secret"
            sni = "sni.com"
            type = "ws"
            host = "host.com"
            path = "/path"
            ssMethod = "aes-256-gcm"
            ssPassword = "sspass"
            encryption = "ss;aes-256-gcm:sspass"
            mux = true
            muxConcurrency = 10
            allowInsecure = false
            name = "TestEntity"
        }

        val entity = ProxyEntity().putBean(bean)
        assertEquals(ProxyEntity.TYPE_TROJAN_GO, entity.type)
        assertEquals(bean, entity.requireBean())

        val bytes = BeanConverters.serialize(entity.requireBean())
        val deserializedBean = BeanConverters.trojanGoDeserialize(bytes)
        assertNotNull(deserializedBean)
        assertEquals(bean.serverAddress, deserializedBean.serverAddress)
        assertEquals(bean.serverPort, deserializedBean.serverPort)
        assertEquals(bean.password, deserializedBean.password)
        assertEquals(bean.type, deserializedBean.type)
        assertEquals(bean.host, deserializedBean.host)
        assertEquals(bean.path, deserializedBean.path)
        assertEquals(bean.ssMethod, deserializedBean.ssMethod)
        assertEquals(bean.ssPassword, deserializedBean.ssPassword)
        assertEquals(bean.mux, deserializedBean.mux)
        assertEquals(bean.muxConcurrency, deserializedBean.muxConcurrency)
    }

    @Test
    fun `buildSingBoxOutbound and parseOutbound should round trip TrojanGoBean`() = runTest {
        val original = TrojanGoBean().apply {
            serverAddress = "outbound.trojan.org"
            serverPort = 443
            password = "my_password"
            sni = "outbound.trojan.org"
            type = "ws"
            host = "ws.trojan.org"
            path = "/trojan-path"
            ssMethod = "aes-128-gcm"
            ssPassword = "my_ss_password"
            encryption = "ss;aes-128-gcm:my_ss_password"
            mux = true
            muxConcurrency = 8
            allowInsecure = true
            name = "ExportNode"
        }

        val jsonStr = buildSingBoxOutbound(original)
        assertTrue(jsonStr.contains(""""type": "trojan-go"""") || jsonStr.contains(""""type":"trojan-go""""))

        val jsonMap = kxs.parseToJsonElement(jsonStr).toJsonMapKxs()
        val parsedBean = parseOutbound(jsonMap) as? TrojanGoBean
        assertNotNull(parsedBean)
        assertEquals(original.serverAddress, parsedBean.serverAddress)
        assertEquals(original.serverPort, parsedBean.serverPort)
        assertEquals(original.password, parsedBean.password)
        assertEquals(original.sni, parsedBean.sni)
        assertEquals(original.type, parsedBean.type)
        assertEquals(original.host, parsedBean.host)
        assertEquals(original.path, parsedBean.path)
        assertEquals(original.ssMethod, parsedBean.ssMethod)
        assertEquals(original.ssPassword, parsedBean.ssPassword)
        assertEquals(original.mux, parsedBean.mux)
        assertEquals(original.allowInsecure, parsedBean.allowInsecure)
    }

    @Test
    fun `parseClashProxy should parse trojan-go proxy and trojan with trojan-go plugin`() {
        val clashMap = mapOf(
            "name" to "ClashTrojanGo",
            "type" to "trojan-go",
            "server" to "clash.trojan.org",
            "port" to 8443,
            "password" to "clash_pass",
            "sni" to "clash.trojan.org",
            "skip-cert-verify" to true,
            "network" to "ws",
            "ws-opts" to mapOf(
                "path" to "/ws-clash",
                "headers" to mapOf("Host" to "clash-host.org")
            ),
            "shadowsocks" to mapOf(
                "enabled" to true,
                "method" to "chacha20-ietf-poly1305",
                "password" to "clash_ss"
            ),
            "mux" to mapOf(
                "enabled" to true,
                "concurrency" to 16
            )
        )

        val bean = parseClashProxy(clashMap) as? TrojanGoBean
        assertNotNull(bean)
        assertEquals("ClashTrojanGo", bean.name)
        assertEquals("clash.trojan.org", bean.serverAddress)
        assertEquals(8443, bean.serverPort)
        assertEquals("clash_pass", bean.password)
        assertEquals("clash.trojan.org", bean.sni)
        assertTrue(bean.allowInsecure)
        assertEquals("ws", bean.type)
        assertEquals("/ws-clash", bean.path)
        assertEquals("clash-host.org", bean.host)
        assertEquals("chacha20-ietf-poly1305", bean.ssMethod)
        assertEquals("clash_ss", bean.ssPassword)
        assertTrue(bean.mux)
        assertEquals(16, bean.muxConcurrency)

        val clashPluginMap = mapOf(
            "name" to "ClashPluginTrojan",
            "type" to "trojan",
            "server" to "plugin.trojan.org",
            "port" to 443,
            "password" to "plugin_pass",
            "plugin" to "trojan-go",
            "plugin-opts" to mapOf(
                "mode" to "ws",
                "host" to "plugin-host.org",
                "path" to "/plugin-path",
                "encryption" to "ss;aes-256-gcm:plugin_ss",
                "mux" to true
            )
        )
        val pluginBean = parseClashProxy(clashPluginMap) as? TrojanGoBean
        assertNotNull(pluginBean)
        assertEquals("ClashPluginTrojan", pluginBean.name)
        assertEquals("plugin.trojan.org", pluginBean.serverAddress)
        assertEquals("ws", pluginBean.type)
        assertEquals("plugin-host.org", pluginBean.host)
        assertEquals("/plugin-path", pluginBean.path)
        assertEquals("aes-256-gcm", pluginBean.ssMethod)
        assertEquals("plugin_ss", pluginBean.ssPassword)
        assertTrue(pluginBean.mux)
    }

    @Test
    fun `parseProxies should parse trojango link and trojan link with encryption`() = runTest {
        val text = """
            trojango://pass123@example1.com:443/?sni=sni1.com#Node1
            trojan://pass456@example2.com:443/?encryption=ss%3Baes-128-gcm%3Asspass#Node2
        """.trimIndent()

        val list = parseProxies(text)
        assertEquals(2, list.size)
        assertTrue(list[0] is TrojanGoBean)
        assertEquals("example1.com", list[0].serverAddress)
        assertEquals("pass123", (list[0] as TrojanGoBean).password)

        assertTrue(list[1] is TrojanGoBean)
        assertEquals("example2.com", list[1].serverAddress)
        assertEquals("aes-128-gcm", (list[1] as TrojanGoBean).ssMethod)
        assertEquals("sspass", (list[1] as TrojanGoBean).ssPassword)
    }
}

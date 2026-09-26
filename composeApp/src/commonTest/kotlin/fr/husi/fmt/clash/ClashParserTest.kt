package fr.husi.fmt.clash

import fr.husi.fmt.http.HttpBean
import fr.husi.fmt.hysteria.HysteriaBean
import fr.husi.fmt.juicity.JuicityBean
import fr.husi.fmt.shadowsocks.ShadowsocksBean
import fr.husi.fmt.socks.SOCKSBean
import fr.husi.fmt.trojan.TrojanBean
import fr.husi.fmt.tuic.TuicBean
import fr.husi.fmt.v2ray.VLESSBean
import fr.husi.fmt.v2ray.VMessBean
import fr.husi.group.RawUpdater
import fr.husi.ktx.b64EncodeOneLine
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ClashParserTest {

    @Test
    fun `parseClashConfig should parse YAML proxies`() = runBlocking {
        val yaml = """
            proxies:
              - name: "SS Node"
                type: ss
                server: 1.2.3.4
                port: 8388
                cipher: aes-256-gcm
                password: "secretpassword"
                udp: true

              - name: "VMess Node"
                type: vmess
                server: 5.6.7.8
                port: 443
                uuid: b831381d-6324-4d53-ad4f-8cda48b30811
                alterId: 0
                cipher: auto
                tls: true
                servername: vmess.example.com
                network: ws
                ws-opts:
                  path: /v2ray
                  headers:
                    Host: vmess.example.com

              - name: "VLESS Node"
                type: vless
                server: 9.10.11.12
                port: 443
                uuid: c942492e-7435-5e64-be5f-9deb59c41922
                flow: xtls-rprx-vision
                tls: true
                servername: vless.example.com
                network: grpc
                grpc-opts:
                  grpc-service-name: my-service

              - name: "Trojan Node"
                type: trojan
                server: 13.14.15.16
                port: 443
                password: "trojanpassword"
                sni: trojan.example.com

              - name: "Hysteria2 Node"
                type: hysteria2
                server: 17.18.19.20
                port: 8443
                password: "hy2password"
                sni: hy2.example.com
                obfs: salamander
                obfs-password: "obfspassword"

              - name: "TUIC Node"
                type: tuic
                server: 21.22.23.24
                port: 8443
                uuid: d053503f-8546-6f75-cf60-0efc60d52033
                password: "tuicpassword"
                sni: tuic.example.com
                congestion-controller: bbr

              - name: "Juicity Node"
                type: juicity
                server: 25.26.27.28
                port: 443
                uuid: e164614a-9657-7a86-d071-1fgd71e63144
                password: "juicitypassword"
                sni: juicity.example.com

              - name: "Socks Node"
                type: socks5
                server: 29.30.31.32
                port: 1080
                username: "socksuser"
                password: "sockspassword"

              - name: "HTTP Node"
                type: http
                server: 33.34.35.36
                port: 8080
                username: "httpuser"
                password: "httppassword"
                tls: true
        """.trimIndent()

        val proxies = assertNotNull(RawUpdater.parseRaw(yaml))
        assertEquals(9, proxies.size)

        val ss = assertIs<ShadowsocksBean>(proxies[0])
        assertEquals("SS Node", ss.name)
        assertEquals("1.2.3.4", ss.serverAddress)
        assertEquals(8388, ss.serverPort)
        assertEquals("aes-256-gcm", ss.method)
        assertEquals("secretpassword", ss.password)

        val vmess = assertIs<VMessBean>(proxies[1])
        assertEquals("VMess Node", vmess.name)
        assertEquals("5.6.7.8", vmess.serverAddress)
        assertEquals(443, vmess.serverPort)
        assertEquals("b831381d-6324-4d53-ad4f-8cda48b30811", vmess.uuid)
        assertEquals("tls", vmess.security)
        assertEquals("vmess.example.com", vmess.sni)
        assertEquals("ws", vmess.v2rayTransport)
        assertEquals("/v2ray", vmess.path)
        assertEquals("vmess.example.com", vmess.host)

        val vless = assertIs<VLESSBean>(proxies[2])
        assertEquals("VLESS Node", vless.name)
        assertEquals("xtls-rprx-vision", vless.flow)
        assertEquals("grpc", vless.v2rayTransport)
        assertEquals("my-service", vless.path)

        val trojan = assertIs<TrojanBean>(proxies[3])
        assertEquals("Trojan Node", trojan.name)
        assertEquals("trojanpassword", trojan.password)
        assertEquals("trojan.example.com", trojan.sni)

        val hy2 = assertIs<HysteriaBean>(proxies[4])
        assertEquals("Hysteria2 Node", hy2.name)
        assertEquals(HysteriaBean.PROTOCOL_VERSION_2, hy2.protocolVersion)
        assertEquals("hy2password", hy2.authPayload)
        assertEquals("hy2.example.com", hy2.sni)
        assertEquals("salamander", hy2.obfsType)
        assertEquals("obfspassword", hy2.obfsPassword)

        val tuic = assertIs<TuicBean>(proxies[5])
        assertEquals("TUIC Node", tuic.name)
        assertEquals("tuicpassword", tuic.token)
        assertEquals("bbr", tuic.congestionController)

        val juicity = assertIs<JuicityBean>(proxies[6])
        assertEquals("Juicity Node", juicity.name)
        assertEquals("juicitypassword", juicity.password)

        val socks = assertIs<SOCKSBean>(proxies[7])
        assertEquals("Socks Node", socks.name)
        assertEquals("socksuser", socks.username)
        assertEquals("sockspassword", socks.password)

        val http = assertIs<HttpBean>(proxies[8])
        assertEquals("HTTP Node", http.name)
        assertEquals("httpuser", http.username)
        assertEquals("httppassword", http.password)
        assertTrue(http.isTLS)
    }

    @Test
    fun `parseRaw should parse base64 encoded Clash YAML config`() = runBlocking {
        val yaml = """
            proxies:
              - name: "Encoded Node"
                type: ss
                server: 1.1.1.1
                port: 8388
                cipher: chacha20-ietf-poly1305
                password: "mypassword"
        """.trimIndent()

        val encoded = yaml.b64EncodeOneLine()
        val proxies = assertNotNull(RawUpdater.parseRaw(encoded))
        val ss = assertIs<ShadowsocksBean>(proxies.single())

        assertEquals("Encoded Node", ss.name)
        assertEquals("1.1.1.1", ss.serverAddress)
        assertEquals("chacha20-ietf-poly1305", ss.method)
    }

    @Test
    fun `parseRaw should parse Clash JSON config`() = runBlocking {
        val json = """
            {
              "proxies": [
                {
                  "name": "JSON SS Node",
                  "type": "ss",
                  "server": "2.2.2.2",
                  "port": 8388,
                  "cipher": "aes-128-gcm",
                  "password": "jsonpassword"
                }
              ]
            }
        """.trimIndent()

        val proxies = assertNotNull(RawUpdater.parseRaw(json))
        val ss = assertIs<ShadowsocksBean>(proxies.single())

        assertEquals("JSON SS Node", ss.name)
        assertEquals("2.2.2.2", ss.serverAddress)
        assertEquals("aes-128-gcm", ss.method)
    }
}

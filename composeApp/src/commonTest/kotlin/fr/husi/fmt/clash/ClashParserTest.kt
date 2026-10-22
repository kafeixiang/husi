package fr.husi.fmt.clash

import fr.husi.fmt.anytls.AnyTLSBean
import fr.husi.fmt.direct.DirectBean
import fr.husi.fmt.http.HttpBean
import fr.husi.fmt.hysteria.HysteriaBean
import fr.husi.fmt.juicity.JuicityBean
import fr.husi.fmt.naive.NaiveBean
import fr.husi.fmt.shadowsocks.ShadowsocksBean
import fr.husi.fmt.snell.SnellBean
import fr.husi.fmt.socks.SOCKSBean
import fr.husi.fmt.ssh.SSHBean
import fr.husi.fmt.ssr.SSRBean
import fr.husi.fmt.trojan.TrojanBean
import fr.husi.fmt.trusttunnel.TrustTunnelBean
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

    @Test
    fun `parseRaw should parse Clash YAML with inline flow JSON and compact numbers`() = runBlocking {
        val yaml = """
            proxies:
              - {"name":"SSR Flow Node","type":"ssr","server":"ssr.example.com","port":30806,"cipher":"chacha20-ietf","password":"dummypassword","protocol":"auth_aes128_sha1","protocol-param":"123456:dummy","obfs":"tls1.2_ticket_auth","obfs-param":"dummy.example.com","udp":true,"tags":"hk"}
              - {"name":"VMess Flow Node","type":"vmess","server":"vmess.example.com","port":31449,"uuid":"00000000-0000-0000-0000-000000000000","alterId":0,"cipher":"auto","udp":true,"tags":"tag","network":"ws","ws-opts":{"path":"/dummy-path"},"skip-cert-verify":false}
        """.trimIndent()

        val proxies = assertNotNull(RawUpdater.parseRaw(yaml))
        assertEquals(2, proxies.size)

        val ssr = assertIs<SSRBean>(proxies[0])
        assertEquals("SSR Flow Node", ssr.name)
        assertEquals("ssr.example.com", ssr.serverAddress)
        assertEquals(30806, ssr.serverPort)
        assertEquals("chacha20-ietf", ssr.method)
        assertEquals("dummypassword", ssr.password)
        assertEquals("auth_aes128_sha1", ssr.protocol)
        assertEquals("123456:dummy", ssr.protocolParam)
        assertEquals("tls1.2_ticket_auth", ssr.obfs)
        assertEquals("dummy.example.com", ssr.obfsParam)

        val vmess = assertIs<VMessBean>(proxies[1])
        assertEquals("VMess Flow Node", vmess.name)
        assertEquals("vmess.example.com", vmess.serverAddress)
        assertEquals(31449, vmess.serverPort)
        assertEquals(0, vmess.alterId)
        assertEquals("/dummy-path", vmess.path)
    }

    @Test
    fun `parseRaw should parse Surge and Shadowrocket configurations`() = runBlocking {
        val surgeConfig = """
            [General]
            loglevel = notify

            [Proxy]
            Surge-SS = ss, 1.1.1.1, 8388, encrypt-method=aes-256-gcm, password=sspass, udp-relay=true
            Surge-VMess = vmess, 2.2.2.2, 443, username=00000000-0000-0000-0000-000000000001, ws=true, ws-path=/ws, tls=true, sni=vmess.example.com
            Surge-Trojan = trojan, 3.3.3.3, 443, password=trojanpass, sni=trojan.example.com, skip-cert-verify=true
            Surge-Hy2 = hysteria2, 4.4.4.4, 8443, password=hy2pass, sni=hy2.example.com, download-bandwidth=100
            Surge-Snell = snell, 5.5.5.5, 443, psk=snellpsk, version=4
            Surge-Http = http, 6.6.6.6, 8080, httpuser, httppass
            Surge-VLESS = vless, 7.7.7.7, 443, 00000000-0000-0000-0000-000000000003, flow=xtls-rprx-vision, tls=true, sni=vless.example.com, pbk=dummyrealitykey, sid=1234
            Surge-Direct = direct

            [Proxy Group]
            Proxy = select, Surge-SS, Surge-VMess
        """.trimIndent()

        val proxies = assertNotNull(RawUpdater.parseRaw(surgeConfig))
        assertEquals(8, proxies.size)

        val ss = assertIs<ShadowsocksBean>(proxies[0])
        assertEquals("Surge-SS", ss.name)
        assertEquals("1.1.1.1", ss.serverAddress)
        assertEquals(8388, ss.serverPort)
        assertEquals("aes-256-gcm", ss.method)
        assertEquals("sspass", ss.password)

        val vmess = assertIs<VMessBean>(proxies[1])
        assertEquals("Surge-VMess", vmess.name)
        assertEquals("2.2.2.2", vmess.serverAddress)
        assertEquals(443, vmess.serverPort)
        assertEquals("00000000-0000-0000-0000-000000000001", vmess.uuid)
        assertEquals("ws", vmess.v2rayTransport)
        assertEquals("/ws", vmess.path)
        assertEquals("vmess.example.com", vmess.sni)
        assertTrue(vmess.isTLS)

        val trojan = assertIs<TrojanBean>(proxies[2])
        assertEquals("Surge-Trojan", trojan.name)
        assertEquals("trojanpass", trojan.password)
        assertEquals("trojan.example.com", trojan.sni)
        assertTrue(trojan.allowInsecure)

        val hy2 = assertIs<HysteriaBean>(proxies[3])
        assertEquals("Surge-Hy2", hy2.name)
        assertEquals("hy2pass", hy2.authPayload)
        assertEquals("hy2.example.com", hy2.sni)

        val snell = assertIs<SnellBean>(proxies[4])
        assertEquals("Surge-Snell", snell.name)
        assertEquals("snellpsk", snell.psk)
        assertEquals(4, snell.version)

        val http = assertIs<HttpBean>(proxies[5])
        assertEquals("Surge-Http", http.name)
        assertEquals("httpuser", http.username)
        assertEquals("httppass", http.password)

        val vless = assertIs<VLESSBean>(proxies[6])
        assertEquals("Surge-VLESS", vless.name)
        assertEquals("7.7.7.7", vless.serverAddress)
        assertEquals(443, vless.serverPort)
        assertEquals("00000000-0000-0000-0000-000000000003", vless.uuid)
        assertEquals("xtls-rprx-vision", vless.flow)
        assertEquals("vless.example.com", vless.sni)
        assertEquals("dummyrealitykey", vless.realityPublicKey)
        assertEquals("1234", vless.realityShortID)
        assertTrue(vless.isTLS)

        val direct = assertIs<DirectBean>(proxies[7])
        assertEquals("Surge-Direct", direct.name)
    }

    @Test
    fun `parseRaw should parse Quantumult X configuration`() = runBlocking {
        val qxConfig = """
            [general]
            server_check_url=http://cp.cloudflare.com/generate_204

            [server_local]
            shadowsocks=1.1.1.1:8388, method=aes-256-gcm, password=sspass, tag=QX-SS
            shadowsocks=2.2.2.2:8388, method=aes-256-cfb, password=ssrpass, ssr-protocol=auth_aes128_sha1, ssr-protocol-param=123:abc, obfs=tls1.2_ticket_auth, obfs-host=ssr.example.com, tag=QX-SSR
            vmess=3.3.3.3:443, method=none, password=00000000-0000-0000-0000-000000000002, obfs=ws, obfs-host=qx-vmess.example.com, obfs-uri=/ws, over-tls=true, tls-host=qx-vmess.example.com, tag=QX-VMess
            trojan=4.4.4.4:443, password=trojanpass, over-tls=true, tls-host=qx-trojan.example.com, tag=QX-Trojan
            vless=7.7.7.7:443, password=00000000-0000-0000-0000-000000000003, flow=xtls-rprx-vision, over-tls=true, tls-host=qx-vless.example.com, pbk=dummyrealitykey, sid=5678, tag=QX-VLESS
            http=5.5.5.5:8080, username=httpuser, password=httppass, tag=QX-Http
            socks5=6.6.6.6:1080, username=socksuser, password=sockspass, tag=QX-Socks5

            [filter_local]
            final, direct
        """.trimIndent()

        val proxies = assertNotNull(RawUpdater.parseRaw(qxConfig))
        assertEquals(7, proxies.size)

        val ss = assertIs<ShadowsocksBean>(proxies[0])
        assertEquals("QX-SS", ss.name)
        assertEquals("1.1.1.1", ss.serverAddress)
        assertEquals(8388, ss.serverPort)
        assertEquals("aes-256-gcm", ss.method)
        assertEquals("sspass", ss.password)

        val ssr = assertIs<SSRBean>(proxies[1])
        assertEquals("QX-SSR", ssr.name)
        assertEquals("2.2.2.2", ssr.serverAddress)
        assertEquals(8388, ssr.serverPort)
        assertEquals("auth_aes128_sha1", ssr.protocol)
        assertEquals("123:abc", ssr.protocolParam)
        assertEquals("tls1.2_ticket_auth", ssr.obfs)
        assertEquals("ssr.example.com", ssr.obfsParam)

        val vmess = assertIs<VMessBean>(proxies[2])
        assertEquals("QX-VMess", vmess.name)
        assertEquals("3.3.3.3", vmess.serverAddress)
        assertEquals(443, vmess.serverPort)
        assertEquals("00000000-0000-0000-0000-000000000002", vmess.uuid)
        assertEquals("ws", vmess.v2rayTransport)
        assertEquals("qx-vmess.example.com", vmess.host)
        assertEquals("/ws", vmess.path)
        assertTrue(vmess.isTLS)

        val trojan = assertIs<TrojanBean>(proxies[3])
        assertEquals("QX-Trojan", trojan.name)
        assertEquals("4.4.4.4", trojan.serverAddress)
        assertEquals("trojanpass", trojan.password)
        assertEquals("qx-trojan.example.com", trojan.sni)

        val qxVless = assertIs<VLESSBean>(proxies[4])
        assertEquals("QX-VLESS", qxVless.name)
        assertEquals("7.7.7.7", qxVless.serverAddress)
        assertEquals(443, qxVless.serverPort)
        assertEquals("00000000-0000-0000-0000-000000000003", qxVless.uuid)
        assertEquals("xtls-rprx-vision", qxVless.flow)
        assertEquals("qx-vless.example.com", qxVless.sni)
        assertEquals("dummyrealitykey", qxVless.realityPublicKey)
        assertEquals("5678", qxVless.realityShortID)
        assertTrue(qxVless.isTLS)

        val http = assertIs<HttpBean>(proxies[5])
        assertEquals("QX-Http", http.name)
        assertEquals("httpuser", http.username)
        assertEquals("httppass", http.password)

        val socks5 = assertIs<SOCKSBean>(proxies[6])
        assertEquals("QX-Socks5", socks5.name)
        assertEquals("socksuser", socks5.username)
        assertEquals("sockspass", socks5.password)
    }

    @Test
    fun `parseRaw should parse Clash YAML with new protocols`() = runBlocking {
        val yaml = """
            proxies:
              - name: "AnyTLS Node"
                type: anytls
                server: 1.1.1.1
                port: 443
                password: "anytlspassword"
                sni: anytls.example.com
                alpn: [h2, http/1.1]
                client-fingerprint: chrome

              - name: "Naive Node"
                type: naive
                server: 2.2.2.2
                port: 443
                username: "naiveuser"
                password: "naivepassword"
                sni: naive.example.com

              - name: "TrustTunnel Node"
                type: trusttunnel
                server: 3.3.3.3
                port: 443
                username: "ttuser"
                password: "ttpassword"
                sni: tt.example.com

              - name: "SSH Node"
                type: ssh
                server: 4.4.4.4
                port: 22
                username: "sshuser"
                password: "sshpassword"
        """.trimIndent()

        val proxies = assertNotNull(RawUpdater.parseRaw(yaml))
        assertEquals(4, proxies.size)

        val anytls = assertIs<AnyTLSBean>(proxies[0])
        assertEquals("AnyTLS Node", anytls.name)
        assertEquals("1.1.1.1", anytls.serverAddress)
        assertEquals(443, anytls.serverPort)
        assertEquals("anytlspassword", anytls.password)
        assertEquals("anytls.example.com", anytls.serverName)
        assertEquals("chrome", anytls.utlsFingerprint)

        val naive = assertIs<NaiveBean>(proxies[1])
        assertEquals("Naive Node", naive.name)
        assertEquals("naiveuser", naive.username)
        assertEquals("naivepassword", naive.password)
        assertEquals("naive.example.com", naive.sni)

        val tt = assertIs<TrustTunnelBean>(proxies[2])
        assertEquals("TrustTunnel Node", tt.name)
        assertEquals("ttuser", tt.username)
        assertEquals("ttpassword", tt.password)
        assertEquals("tt.example.com", tt.serverName)

        val ssh = assertIs<SSHBean>(proxies[3])
        assertEquals("SSH Node", ssh.name)
        assertEquals("sshuser", ssh.username)
        assertEquals("sshpassword", ssh.password)
        assertEquals(22, ssh.serverPort)
    }

    @Test
    fun `parseRaw should parse Clash YAML VLESS with Reality and gRPC`() = runBlocking {
        val yaml = """
            proxies:
              - name: "Clash VLESS Reality"
                type: vless
                server: 8.8.8.8
                port: 443
                uuid: "00000000-0000-0000-0000-000000000005"
                flow: "xtls-rprx-vision"
                tls: true
                servername: "vless.example.com"
                client-fingerprint: "chrome"
                reality-opts:
                  public-key: "dummyrealitykey"
                  short-id: "abcd"
                network: grpc
                grpc-opts:
                  grpc-service-name: "grpc-service"
        """.trimIndent()

        val proxies = assertNotNull(RawUpdater.parseRaw(yaml))
        assertEquals(1, proxies.size)

        val vless = assertIs<VLESSBean>(proxies[0])
        assertEquals("Clash VLESS Reality", vless.name)
        assertEquals("8.8.8.8", vless.serverAddress)
        assertEquals(443, vless.serverPort)
        assertEquals("00000000-0000-0000-0000-000000000005", vless.uuid)
        assertEquals("xtls-rprx-vision", vless.flow)
        assertEquals("vless.example.com", vless.sni)
        assertEquals("chrome", vless.utlsFingerprint)
        assertEquals("dummyrealitykey", vless.realityPublicKey)
        assertEquals("abcd", vless.realityShortID)
        assertEquals("grpc", vless.v2rayTransport)
        assertEquals("grpc-service", vless.path)
        assertTrue(vless.isTLS)
    }
}

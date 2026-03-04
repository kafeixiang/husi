package fr.husi.fmt

import fr.husi.database.DataStore
import fr.husi.database.ProxyEntity
import fr.husi.database.ProxyGroup
import fr.husi.database.SagerDatabase
import fr.husi.fmt.internal.ProxySetBean
import fr.husi.fmt.socks.SOCKSBean
import fr.husi.ktx.applyDefaultValues
import fr.husi.repository.FakeRepository
import fr.husi.repository.repo
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ConfigBuilderTest {

    @BeforeTest
    fun setup() = runBlocking {
        repo = FakeRepository()

        DataStore.configurationStore.reset()
        SagerDatabase.proxyDao.reset()
        SagerDatabase.groupDao.reset()
        SagerDatabase.rulesDao.reset()
        SagerDatabase.assetDao.reset()
        SagerDatabase.pluginDao.reset()
    }

    @Test
    fun `buildConfig should wire front and landing around proxy set`() = runBlocking {
        val group = ProxyGroup(name = "group").applyDefaultValues()
        group.id = SagerDatabase.groupDao.createGroup(group)

        val memberA = createSocksProxy(
            groupId = group.id,
            order = 1,
            name = "member-a",
            host = "1.1.1.1",
            port = 1081,
        )
        val memberB = createSocksProxy(
            groupId = group.id,
            order = 2,
            name = "member-b",
            host = "2.2.2.2",
            port = 1082,
        )
        val front = createSocksProxy(
            groupId = group.id,
            order = 3,
            name = "front",
            host = "3.3.3.3",
            port = 1083,
        )
        val landing = createSocksProxy(
            groupId = group.id,
            order = 4,
            name = "landing",
            host = "4.4.4.4",
            port = 1084,
        )

        val proxySet = ProxyEntity(groupId = group.id, userOrder = 5).putBean(
            ProxySetBean().apply {
                name = "set-main"
                management = ProxySetBean.MANAGEMENT_SELECTOR
                type = ProxySetBean.TYPE_LIST
                proxies = listOf(memberA.id, memberB.id)
            }.applyDefaultValues(),
        )
        proxySet.id = SagerDatabase.proxyDao.addProxy(proxySet)

        group.frontProxy = front.id
        group.landingProxy = landing.id
        SagerDatabase.groupDao.updateGroup(group)

        val result = buildConfig(proxySet, forTest = true)

        assertEquals("landing", result.mainTag)
        assertEquals(proxySet.id, result.tagToID["set-main"])
        assertEquals(landing.id, result.tagToID["landing"])

        val trafficGroup = result.trafficMap["set-main"]
        assertNotNull(trafficGroup)
        assertEquals(landing.id, trafficGroup.last().id)

        val root = Json.parseToJsonElement(result.config).jsonObject
        val outbounds = root["outbounds"]!!.jsonArray.map { it.jsonObject }
        fun outboundByTag(tag: String) = outbounds.first { it["tag"]?.jsonPrimitive?.content == tag }

        val selector = outboundByTag("set-main")
        val selectorChildren = selector["outbounds"]!!.jsonArray.map { it.jsonPrimitive.content }.toSet()
        assertEquals(setOf("member-a", "member-b"), selectorChildren)
        assertTrue("front" !in selectorChildren)
        assertTrue("landing" !in selectorChildren)

        assertEquals("front", outboundByTag("member-a")["detour"]?.jsonPrimitive?.content)
        assertEquals("front", outboundByTag("member-b")["detour"]?.jsonPrimitive?.content)
        assertEquals("set-main", outboundByTag("landing")["detour"]?.jsonPrimitive?.content)
    }

    private suspend fun createSocksProxy(
        groupId: Long,
        order: Long,
        name: String,
        host: String,
        port: Int,
    ): ProxyEntity {
        val proxy = ProxyEntity(groupId = groupId, userOrder = order).putBean(
            SOCKSBean().apply {
                this.name = name
                serverAddress = host
                serverPort = port
            }.applyDefaultValues(),
        )
        proxy.id = SagerDatabase.proxyDao.addProxy(proxy)
        return proxy
    }
}

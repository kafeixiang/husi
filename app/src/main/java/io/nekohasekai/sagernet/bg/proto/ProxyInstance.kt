package io.nekohasekai.sagernet.bg.proto

import io.nekohasekai.sagernet.BuildConfig
import io.nekohasekai.sagernet.bg.BaseService
import io.nekohasekai.sagernet.bg.LocalResolver
import io.nekohasekai.sagernet.bg.ServiceNotification
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import kotlinx.coroutines.runBlocking
import libcore.Libcore
import moe.matsuri.nb4a.utils.JavaUtil

class ProxyInstance(profile: ProxyEntity, var service: BaseService.Interface? = null) :
    BoxInstance(profile) {

    var lastSelectorGroupId = -1L
    var displayProfileName = ServiceNotification.genTitle(profile)

    var trafficLooper: TrafficLooper? = null
    var dashboardStatusLooper: DashboardStatusLooper? = null

    override fun buildConfig() {
        super.buildConfig()
        lastSelectorGroupId = super.config.selectorGroupId
        Logs.d(config.config)
        if (BuildConfig.DEBUG) Logs.d(JavaUtil.gson.toJson(config.trafficMap))
    }

    override suspend fun init(isVPN: Boolean) {
        super.init(isVPN)
        pluginConfigs.forEach { (_, plugin) ->
            val (_, content) = plugin
            Logs.d(content)
        }
    }

    override suspend fun loadConfig() {
        Libcore.registerLocalDNSTransport(LocalResolver)
        super.loadConfig()
    }

    override fun launch() {
        super.launch() // start box
        runOnDefaultDispatcher {
            service?.let {
                trafficLooper = TrafficLooper(it.data, this)
                dashboardStatusLooper = DashboardStatusLooper(it.data, this)
            }
            trafficLooper?.start()
        }
    }

    override fun close() {
        Libcore.registerLocalDNSTransport(null)
        super.close()
        runBlocking {
            trafficLooper?.stop()
            trafficLooper = null

            dashboardStatusLooper?.stop()
            dashboardStatusLooper = null
        }
    }
}

package io.nekohasekai.sagernet.fmt.internal

import io.nekohasekai.sagernet.fmt.SingBoxOptions

fun buildSingBoxOutboundGroupBean(
    bean: GroupBean,
    outbounds: List<String>,
): SingBoxOptions.Outbound {
    return when (bean.management) {
        GroupBean.MANAGEMENT_SELECTOR -> SingBoxOptions.Outbound_SelectorOptions().apply {
            type = SingBoxOptions.TYPE_SELECTOR
            this.outbounds = outbounds
            interrupt_exist_connections = bean.interruptExistConnections
        }

        GroupBean.MANAGEMENT_URLTEST -> SingBoxOptions.Outbound_URLTestOptions().apply {
            type = SingBoxOptions.TYPE_URLTEST
            this.outbounds = outbounds
            url = bean.testURL
            interval = bean.testInterval
            tolerance = bean.testTolerance
            idle_timeout = bean.testIdleTimeout
            interrupt_exist_connections = bean.interruptExistConnections
        }

        GroupBean.MANAGEMENT_BALANCER -> SingBoxOptions.Outbound_BalancerOptions().apply {
            type = SingBoxOptions.TYPE_BALANCER
            this.outbounds = outbounds
        }

        else -> throw IllegalStateException()
    }
}
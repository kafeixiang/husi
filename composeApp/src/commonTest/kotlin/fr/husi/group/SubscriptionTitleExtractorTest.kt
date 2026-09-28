package fr.husi.group

import kotlin.test.Test
import kotlin.test.assertEquals

class SubscriptionTitleExtractorTest {

    @Test
    fun `decodeHeaderTitle should handle base64 encoded title`() {
        val raw = "base64:TXkgQWlycG9ydA=="
        assertEquals("My Airport", SubscriptionTitleExtractor.decodeHeaderTitle(raw))
    }

    @Test
    fun `decodeHeaderTitle should handle url encoded title with UTF-8 prefix`() {
        val raw = "UTF-8''%E6%88%91%E7%9A%84%E6%9C%BA%E5%9C%BA"
        assertEquals("我的机场", SubscriptionTitleExtractor.decodeHeaderTitle(raw))
    }

    @Test
    fun `decodeHeaderTitle should handle url encoded title without prefix`() {
        val raw = "%E6%88%91%E7%9A%84%E6%9C%BA%E5%9C%BA"
        assertEquals("我的机场", SubscriptionTitleExtractor.decodeHeaderTitle(raw))
    }

    @Test
    fun `decodeHeaderTitle should handle plain string`() {
        val raw = "  My Plain Airport  "
        assertEquals("My Plain Airport", SubscriptionTitleExtractor.decodeHeaderTitle(raw))
    }

    @Test
    fun `extractFilenameFromContentDisposition should extract filename`() {
        val disposition = "attachment; filename=\"MyAirport.yaml\""
        assertEquals("MyAirport", SubscriptionTitleExtractor.extractFilenameFromContentDisposition(disposition))
    }

    @Test
    fun `extractFilenameFromContentDisposition should extract filename star`() {
        val disposition = "attachment; filename*=UTF-8''%E6%88%91%E7%9A%84%E6%9C%BA%E5%9C%BA.yaml"
        assertEquals("我的机场", SubscriptionTitleExtractor.extractFilenameFromContentDisposition(disposition))
    }

    @Test
    fun `extractTitleFromContent should extract profile-title comment`() {
        val content = """
            # profile-title: My Comment Airport
            proxies:
              - name: SS
                type: ss
        """.trimIndent()
        assertEquals("My Comment Airport", SubscriptionTitleExtractor.extractTitleFromContent(content))
    }
}

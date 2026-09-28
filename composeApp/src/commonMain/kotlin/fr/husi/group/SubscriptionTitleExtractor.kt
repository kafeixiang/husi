package fr.husi.group

import fr.husi.ktx.b64DecodeToString
import fr.husi.ktx.blankAsNull
import fr.husi.libcore.Libcore
import java.net.URLDecoder

object SubscriptionTitleExtractor {

    fun decodeHeaderTitle(rawHeader: String?): String? {
        if (rawHeader.isNullOrBlank()) return null
        var trimmed = rawHeader.trim()

        if (trimmed.startsWith("base64:", ignoreCase = true)) {
            runCatching {
                val b64 = trimmed.substring(7).trim()
                val decoded = b64.b64DecodeToString().trim()
                if (decoded.isNotBlank()) return decoded
            }
        }

        if (trimmed.startsWith("UTF-8''", ignoreCase = true)) {
            trimmed = trimmed.substring(7)
        }

        if (trimmed.contains("%")) {
            runCatching {
                val decoded = Libcore.parseURL("http://dummy/?title=$trimmed").queryParameter("title")
                if (!decoded.isNullOrBlank()) return decoded.trim()
            }
            runCatching {
                @Suppress("DEPRECATION")
                val decoded = URLDecoder.decode(trimmed, "UTF-8")
                if (decoded.isNotBlank()) return decoded.trim()
            }
        }

        return trimmed.blankAsNull()
    }

    fun extractFilenameFromContentDisposition(disposition: String?): String? {
        if (disposition.isNullOrBlank()) return null

        var filename: String? = null
        if (disposition.contains("filename*=", ignoreCase = true)) {
            val part = disposition.substringAfter("filename*=", "").substringBefore(";")
            filename = decodeHeaderTitle(part)
        }
        if (filename.isNullOrBlank() && disposition.contains("filename=", ignoreCase = true)) {
            val part = disposition.substringAfter("filename=", "").substringBefore(";").trim().removeSurrounding("\"").removeSurrounding("'")
            filename = decodeHeaderTitle(part)
        }

        if (!filename.isNullOrBlank()) {
            val name = filename.removeSuffix(".yaml")
                .removeSuffix(".yml")
                .removeSuffix(".json")
                .removeSuffix(".txt")
                .removeSuffix(".conf")
                .trim()
            return name.blankAsNull()
        }
        return null
    }

    fun extractTitleFromContent(content: String?): String? {
        if (content.isNullOrBlank()) return null
        for (line in content.lineSequence().take(30)) {
            val trimmed = line.trim()
            if (trimmed.startsWith("#")) {
                val comment = trimmed.removePrefix("#").trim()
                if (comment.startsWith("profile-title:", ignoreCase = true)) {
                    return decodeHeaderTitle(comment.substringAfter("profile-title:").trim())
                }
                if (comment.startsWith("subscription-title:", ignoreCase = true)) {
                    return decodeHeaderTitle(comment.substringAfter("subscription-title:").trim())
                }
                if (comment.startsWith("title:", ignoreCase = true)) {
                    return decodeHeaderTitle(comment.substringAfter("title:").trim())
                }
            } else if (trimmed.startsWith("profile-title:", ignoreCase = true)) {
                return decodeHeaderTitle(trimmed.substringAfter("profile-title:").trim())
            }
        }
        return null
    }

    fun extractTitle(
        profileTitleHeader: String?,
        contentDispositionHeader: String?,
        content: String?,
    ): String? {
        return decodeHeaderTitle(profileTitleHeader)
            ?: extractFilenameFromContentDisposition(contentDispositionHeader)
            ?: extractTitleFromContent(content)
    }
}

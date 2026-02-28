package fr.husi.plugin

class PluginOptions : HashMap<String, String?> {
    constructor() : super()
    constructor(options: String?) : super() {
        if (options.isNullOrBlank()) return
        options.split(';').forEach {
            val pair = it.split('=', limit = 2)
            if (pair[0].isNotEmpty()) {
                val key = decode(pair[0])
                val value = if (pair.size > 1) decode(pair[1]) else null
                put(key, value)
            }
        }
    }

    override fun toString(): String = map { (key, value) ->
        val encodedKey = encode(key)
        if (value == null) encodedKey else "$encodedKey=${encode(value)}"
    }.joinToString(";")

    companion object {
        // Simple manual encoding/decoding for plugin options (usually just URI-like chars)
        private fun encode(s: String): String {
            return s.replace("%", "%25")
                .replace(";", "%3B")
                .replace("=", "%3D")
        }

        private fun decode(s: String): String {
            return s.replace("%3D", "=")
                .replace("%3B", ";")
                .replace("%25", "%")
        }
    }
}

package fr.husi.fmt.clash

object YamlParser {

    private data class Line(val indent: Int, val text: String)

    fun parse(yamlText: String): Any? {
        val rawLines = yamlText.lines()
        val lines = mutableListOf<Line>()

        for (raw in rawLines) {
            val lineWithoutComment = removeComment(raw)
            val trimmed = lineWithoutComment.trim()
            if (trimmed.isEmpty() || trimmed == "---" || trimmed == "...") continue

            val expanded = lineWithoutComment.replace("\t", "  ")
            val indent = expanded.takeWhile { it == ' ' }.length
            lines.add(Line(indent, trimmed))
        }

        if (lines.isEmpty()) return null

        val (result, _) = parseBlock(lines, 0, lines[0].indent)
        return result
    }

    private fun removeComment(line: String): String {
        var inSingleQuote = false
        var inDoubleQuote = false
        var escape = false

        for (i in line.indices) {
            val c = line[i]
            if (escape) {
                escape = false
                continue
            }
            if (c == '\\' && inDoubleQuote) {
                escape = true
                continue
            }
            if (c == '\'' && !inDoubleQuote) {
                inSingleQuote = !inSingleQuote
            } else if (c == '"' && !inSingleQuote) {
                inDoubleQuote = !inDoubleQuote
            } else if (c == '#' && !inSingleQuote && !inDoubleQuote) {
                if (i == 0 || line[i - 1].isWhitespace()) {
                    return line.substring(0, i)
                }
            }
        }
        return line
    }

    private fun parseBlock(lines: List<Line>, startIndex: Int, minIndent: Int): Pair<Any?, Int> {
        if (startIndex >= lines.size) return Pair(null, startIndex)

        val firstLine = lines[startIndex]
        return if (firstLine.text.startsWith("- ") || firstLine.text == "-") {
            parseBlockSequence(lines, startIndex, firstLine.indent)
        } else {
            parseBlockMapping(lines, startIndex, firstLine.indent)
        }
    }

    private fun parseBlockSequence(lines: List<Line>, startIndex: Int, seqIndent: Int): Pair<List<Any?>, Int> {
        val list = mutableListOf<Any?>()
        var index = startIndex

        while (index < lines.size) {
            val line = lines[index]
            if (line.indent < seqIndent) break
            if (line.indent > seqIndent && !line.text.startsWith("- ") && line.text != "-") {
                index++
                continue
            }

            if (line.text.startsWith("- ") || line.text == "-") {
                val itemText = line.text.removePrefix("-").trim()
                if (itemText.isEmpty()) {
                    if (index + 1 < lines.size && lines[index + 1].indent > seqIndent) {
                        val (itemVal, nextIdx) = parseBlock(lines, index + 1, lines[index + 1].indent)
                        list.add(itemVal)
                        index = nextIdx
                    } else {
                        list.add(null)
                        index++
                    }
                } else if (itemText.startsWith("{") || itemText.startsWith("[")) {
                    list.add(parseScalar(itemText))
                    index++
                } else if (containsUnquotedColon(itemText)) {
                    val mapItem = mutableMapOf<String, Any?>()
                    val colonIdx = findUnquotedColon(itemText)
                    val key = unquote(itemText.substring(0, colonIdx).trim())
                    val valText = itemText.substring(colonIdx + 1).trim()

                    if (valText.isEmpty()) {
                        if (index + 1 < lines.size && lines[index + 1].indent > seqIndent) {
                            val (subVal, nextIdx) = parseBlock(lines, index + 1, lines[index + 1].indent)
                            mapItem[key] = subVal
                            index = nextIdx
                        } else {
                            mapItem[key] = null
                            index++
                        }
                    } else {
                        mapItem[key] = parseScalar(valText)
                        index++
                    }

                    val mapItemIndent = line.indent
                    while (index < lines.size) {
                        val subLine = lines[index]
                        if (subLine.indent <= seqIndent) break
                        if (subLine.indent == mapItemIndent && (subLine.text.startsWith("- ") || subLine.text == "-")) break
                        if (containsUnquotedColon(subLine.text)) {
                            val cIdx = findUnquotedColon(subLine.text)
                            val subKey = unquote(subLine.text.substring(0, cIdx).trim())
                            val subValText = subLine.text.substring(cIdx + 1).trim()

                            if (subValText.isEmpty()) {
                                if (index + 1 < lines.size && lines[index + 1].indent > subLine.indent) {
                                    val (subVal, nextIdx) = parseBlock(lines, index + 1, lines[index + 1].indent)
                                    mapItem[subKey] = subVal
                                    index = nextIdx
                                } else {
                                    mapItem[subKey] = null
                                    index++
                                }
                            } else {
                                mapItem[subKey] = parseScalar(subValText)
                                index++
                            }
                        } else {
                            index++
                        }
                    }
                    list.add(mapItem)
                } else {
                    list.add(parseScalar(itemText))
                    index++
                }
            } else {
                break
            }
        }

        return Pair(list, index)
    }

    private fun parseBlockMapping(lines: List<Line>, startIndex: Int, mapIndent: Int): Pair<Map<String, Any?>, Int> {
        val map = mutableMapOf<String, Any?>()
        var index = startIndex

        while (index < lines.size) {
            val line = lines[index]
            if (line.indent < mapIndent) break
            if (line.indent > mapIndent) {
                index++
                continue
            }

            if (containsUnquotedColon(line.text)) {
                val colonIdx = findUnquotedColon(line.text)
                val key = unquote(line.text.substring(0, colonIdx).trim())
                val valText = line.text.substring(colonIdx + 1).trim()

                if (valText.isEmpty()) {
                    if (index + 1 < lines.size && lines[index + 1].indent > mapIndent) {
                        val (subVal, nextIdx) = parseBlock(lines, index + 1, lines[index + 1].indent)
                        map[key] = subVal
                        index = nextIdx
                    } else {
                        map[key] = null
                        index++
                    }
                } else {
                    map[key] = parseScalar(valText)
                    index++
                }
            } else {
                index++
            }
        }

        return Pair(map, index)
    }

    private fun containsUnquotedColon(s: String): Boolean {
        return findUnquotedColon(s) >= 0
    }

    private fun findUnquotedColon(s: String): Int {
        var inSingle = false
        var inDouble = false
        var escape = false
        var bracketDepth = 0

        for (i in s.indices) {
            val c = s[i]
            if (escape) {
                escape = false
                continue
            }
            if (c == '\\' && inDouble) {
                escape = true
                continue
            }
            if (c == '\'' && !inDouble) inSingle = !inSingle
            else if (c == '"' && !inSingle) inDouble = !inDouble
            else if (!inSingle && !inDouble) {
                if (c == '[' || c == '{') bracketDepth++
                else if (c == ']' || c == '}') bracketDepth--
                else if (c == ':' && bracketDepth == 0) {
                    if (i == s.length - 1 || s[i + 1].isWhitespace() || s[i + 1] == '{' || s[i + 1] == '[' || s[i + 1] == '"' || s[i + 1] == '\'') {
                        return i
                    }
                }
            }
        }
        return -1
    }

    fun parseScalar(s: String): Any? {
        val trimmed = s.trim()
        if (trimmed.isEmpty() || trimmed == "null" || trimmed == "~") return null

        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            return parseFlowMapping(trimmed)
        }
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            return parseFlowSequence(trimmed)
        }

        if ((trimmed.startsWith("\"") && trimmed.endsWith("\"")) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
            return unquote(trimmed)
        }

        if (trimmed.equals("true", ignoreCase = true) || trimmed.equals("yes", ignoreCase = true)) return true
        if (trimmed.equals("false", ignoreCase = true) || trimmed.equals("no", ignoreCase = true)) return false

        trimmed.toLongOrNull()?.let { return it }
        trimmed.toDoubleOrNull()?.let { return it }

        return trimmed
    }

    private fun parseFlowMapping(s: String): Map<String, Any?> {
        val inner = s.substring(1, s.length - 1).trim()
        if (inner.isEmpty()) return emptyMap()

        val map = mutableMapOf<String, Any?>()
        val tokens = splitFlowTokens(inner)
        for (token in tokens) {
            val colonIdx = findUnquotedColon(token)
            if (colonIdx >= 0) {
                val k = unquote(token.substring(0, colonIdx).trim())
                val vText = token.substring(colonIdx + 1).trim()
                map[k] = parseScalar(vText)
            }
        }
        return map
    }

    private fun parseFlowSequence(s: String): List<Any?> {
        val inner = s.substring(1, s.length - 1).trim()
        if (inner.isEmpty()) return emptyList()

        val list = mutableListOf<Any?>()
        val tokens = splitFlowTokens(inner)
        for (token in tokens) {
            list.add(parseScalar(token))
        }
        return list
    }

    private fun splitFlowTokens(s: String): List<String> {
        val tokens = mutableListOf<String>()
        var inSingle = false
        var inDouble = false
        var escape = false
        var bracketDepth = 0
        var current = StringBuilder()

        for (i in s.indices) {
            val c = s[i]
            if (escape) {
                current.append(c)
                escape = false
                continue
            }
            if (c == '\\' && inDouble) {
                current.append(c)
                escape = true
                continue
            }
            if (c == '\'' && !inDouble) inSingle = !inSingle
            else if (c == '"' && !inSingle) inDouble = !inDouble
            else if (!inSingle && !inDouble) {
                if (c == '[' || c == '{') bracketDepth++
                else if (c == ']' || c == '}') bracketDepth--

                if (c == ',' && bracketDepth == 0) {
                    tokens.add(current.toString().trim())
                    current = StringBuilder()
                    continue
                }
            }
            current.append(c)
        }
        if (current.isNotBlank()) {
            tokens.add(current.toString().trim())
        }
        return tokens
    }

    private fun unquote(s: String): String {
        val trimmed = s.trim()
        if (trimmed.length >= 2) {
            if ((trimmed.startsWith("\"") && trimmed.endsWith("\"")) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
                val inner = trimmed.substring(1, trimmed.length - 1)
                return if (trimmed.startsWith("\"")) {
                    inner.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n").replace("\\t", "\t")
                } else {
                    inner.replace("''", "'")
                }
            }
        }
        return trimmed
    }
}

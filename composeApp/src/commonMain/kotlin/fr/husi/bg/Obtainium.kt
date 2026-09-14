package fr.husi.bg

import fr.husi.HUSI_REPOSITORY
import fr.husi.ktx.urlSafe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

const val OBTAINIUM_SCHEME = "obtainium"

private const val OBTAINIUM_ADD_APP_PREFIX = "$OBTAINIUM_SCHEME://app/"

private const val KEY_URL = "url"
private const val KEY_AUTHOR = "author"
private const val KEY_NAME = "name"
private const val KEY_ADDITIONAL_SETTINGS = "additionalSettings"
private const val KEY_INCLUDE_PRE_RELEASES = "includePrereleases"
private const val KEY_FILTER_RELEASE_TITLES = "filterReleaseTitlesByRegEx"

private const val NON_PLUGIN_RELEASE_TITLE_PATTERN = "^(?!$PLUGIN_RELEASE_TAG_PREFIX)"

private val obtainiumJson = Json

fun obtainiumAddAppLink(
    includePreReleases: Boolean,
    repository: String = HUSI_REPOSITORY,
): String {
    val additionalSettings = buildJsonObject {
        put(KEY_FILTER_RELEASE_TITLES, NON_PLUGIN_RELEASE_TITLE_PATTERN)
        if (includePreReleases) put(KEY_INCLUDE_PRE_RELEASES, true)
    }
    val app = buildJsonObject {
        put(KEY_URL, githubRepositoryUrl(repository))
        put(KEY_AUTHOR, repository.substringBefore('/'))
        put(KEY_NAME, repository.substringAfter('/'))
        put(KEY_ADDITIONAL_SETTINGS, obtainiumJson.encodeToString(additionalSettings))
    }
    return OBTAINIUM_ADD_APP_PREFIX + obtainiumJson.encodeToString(app).urlSafe()
}

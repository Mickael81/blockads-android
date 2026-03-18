package app.pwhs.blockads.data.remote.models

/**
 * Data model for remote pre-compiled filter lists.
 */
data class FilterList(
    val name: String,
    val id: String,
    val description: String? = null,
    val isEnabled: Boolean = false,
    val isBuiltIn: Boolean = true,
    val category: String? = null,
    val ruleCount: Int = 0,
    val bloomUrl: String,
    val trieUrl: String,
    val cssUrl: String? = null,
    val originalUrl: String? = null
)

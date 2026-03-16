package app.pwhs.blockads.ui.wireguard

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.pwhs.blockads.data.datastore.AppPreferences
import app.pwhs.blockads.data.entities.WireGuardConfig
import app.pwhs.blockads.service.AdBlockVpnService
import app.pwhs.blockads.util.WireGuardConfigParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject

class WireGuardImportViewModel(
    application: Application,
) : AndroidViewModel(application), KoinComponent {

    private val appPrefs: AppPreferences by inject()

    private val _config = MutableStateFlow<WireGuardConfig?>(null)
    val config: StateFlow<WireGuardConfig?> = _config.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    /** Whether WireGuard routing mode is currently active in preferences. */
    private val _isWgActive = MutableStateFlow(false)
    val isWgActive: StateFlow<Boolean> = _isWgActive.asStateFlow()

    /** One-shot UI events. */
    private val _events = MutableSharedFlow<WireGuardUiEvent>()
    val events: SharedFlow<WireGuardUiEvent> = _events.asSharedFlow()

    init {
        // Load current routing mode on init
        viewModelScope.launch {
            val mode = appPrefs.getRoutingModeSnapshot()
            _isWgActive.value = mode == AppPreferences.ROUTING_MODE_WIREGUARD

            // If WireGuard is active, try to load the saved config for display
            if (_isWgActive.value) {
                val json = appPrefs.getWgConfigJsonSnapshot()
                if (json != null) {
                    try {
                        _config.value = WireGuardConfig.fromJson(json)
                    } catch (_: Exception) { /* ignore parse errors */ }
                }
            }
        }
    }

    /**
     * Read a .conf file via SAF URI and parse it into [WireGuardConfig].
     */
    fun importFromUri(uri: Uri) {
        viewModelScope.launch {
            _isLoading.value = true
            _error.value = null
            try {
                val rawText = withContext(Dispatchers.IO) {
                    getApplication<Application>().contentResolver
                        .openInputStream(uri)
                        ?.use { it.bufferedReader(Charsets.UTF_8).readText() }
                        ?: throw Exception("Cannot open input stream")
                }

                if (rawText.isBlank()) {
                    _error.value = "File is empty"
                    _config.value = null
                    return@launch
                }

                val parsed = WireGuardConfigParser.parse(rawText)
                _config.value = parsed
            } catch (e: IllegalArgumentException) {
                _error.value = e.message ?: "Invalid WireGuard configuration"
                _config.value = null
            } catch (e: Exception) {
                _error.value = e.message ?: "Failed to import configuration"
                _config.value = null
            } finally {
                _isLoading.value = false
            }
        }
    }

    /**
     * Save the parsed config to DataStore and set routing mode to WireGuard.
     * The VPN service will pick up the new config on next start (or restart).
     */
    fun saveAndActivate() {
        val cfg = _config.value ?: return
        viewModelScope.launch {
            try {
                val json = cfg.toJson()
                appPrefs.setWgConfigJson(json)
                appPrefs.setRoutingMode(AppPreferences.ROUTING_MODE_WIREGUARD)
                _isWgActive.value = true
                AdBlockVpnService.requestRestart(getApplication())
                _events.emit(WireGuardUiEvent.ConfigSaved)
            } catch (e: Exception) {
                _error.value = "Failed to save config: ${e.message}"
            }
        }
    }

    /**
     * Clear the WireGuard config and switch back to direct (DNS-only) mode.
     */
    fun clearWireGuard() {
        viewModelScope.launch {
            appPrefs.setRoutingMode(AppPreferences.ROUTING_MODE_DIRECT)
            appPrefs.setWgConfigJson(null)
            _isWgActive.value = false
            _config.value = null
            AdBlockVpnService.requestRestart(getApplication())
            _events.emit(WireGuardUiEvent.ConfigCleared)
        }
    }

    fun clearError() {
        _error.value = null
    }
}

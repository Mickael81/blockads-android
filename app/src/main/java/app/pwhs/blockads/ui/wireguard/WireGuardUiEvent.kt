package app.pwhs.blockads.ui.wireguard

/**
 * One-shot UI events for the WireGuard import screen.
 */
sealed class WireGuardUiEvent {
    /** Config saved & routing mode set — UI should navigate back or show success. */
    data object ConfigSaved : WireGuardUiEvent()

    /** Config cleared — UI should reflect that WireGuard is no longer active. */
    data object ConfigCleared : WireGuardUiEvent()
}
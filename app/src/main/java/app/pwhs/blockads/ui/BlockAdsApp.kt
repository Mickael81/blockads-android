package app.pwhs.blockads.ui

import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.material3.Icon
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.sp
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.currentBackStackEntryAsState
import app.pwhs.blockads.R
import app.pwhs.blockads.data.datastore.AppPreferences
import com.ramcosta.composedestinations.DestinationsNavHost
import com.ramcosta.composedestinations.generated.NavGraphs
import com.ramcosta.composedestinations.generated.destinations.DnsProviderScreenDestination
import com.ramcosta.composedestinations.generated.destinations.FilterSetupScreenDestination
import com.ramcosta.composedestinations.generated.destinations.FirewallScreenDestination
import com.ramcosta.composedestinations.generated.destinations.HomeScreenDestination
import com.ramcosta.composedestinations.generated.destinations.SettingsScreenDestination
import com.ramcosta.composedestinations.navigation.dependency
import com.ramcosta.composedestinations.rememberNavHostEngine
import com.ramcosta.composedestinations.spec.Direction
import org.koin.compose.koinInject
import timber.log.Timber

sealed class Screen(
    val destination: Direction,
    val route: String,
    @StringRes val labelRes: Int,
    @DrawableRes val icon: Int,
) {
    data object Home :
        Screen(
            destination = HomeScreenDestination(),
            route = HomeScreenDestination.route,
            labelRes = R.string.nav_home,
            icon = R.drawable.ic_home,
        )

    data object FilterSetup : Screen(
        destination = FilterSetupScreenDestination(),
        route = FilterSetupScreenDestination.route,
        labelRes = R.string.nav_filter,
        icon = R.drawable.ic_shield,
    )

    data object Firewall : Screen(
        destination = FirewallScreenDestination(),
        route = FirewallScreenDestination.route,
        labelRes = R.string.settings_firewall,
        icon = R.drawable.ic_fire,
    )

    data object Whitelist : Screen(
        destination = DnsProviderScreenDestination(),
        route = DnsProviderScreenDestination.route,
        labelRes = R.string.dns_provider_title,
        icon = R.drawable.ic_dns,
    )


    data object Settings :
        Screen(
            destination = SettingsScreenDestination(),
            route = SettingsScreenDestination.route,
            labelRes = R.string.nav_settings,
            icon = R.drawable.ic_setting,
        )
}

@Composable
fun BlockAdsApp(onRequestVpnPermission: () -> Unit, modifier: Modifier = Modifier) {
    val engine = rememberNavHostEngine()
    val navController = engine.rememberNavController()
    val screens =
        listOf(Screen.Home, Screen.FilterSetup, Screen.Firewall, Screen.Whitelist, Screen.Settings)
    val newBackStackEntry by navController.currentBackStackEntryAsState()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentDestination = navBackStackEntry?.destination
    val route = newBackStackEntry?.destination?.route
    val showBottomBar = route in listOf(
        HomeScreenDestination.route,
        FilterSetupScreenDestination.route,
        FirewallScreenDestination.route,
        DnsProviderScreenDestination.route,
        SettingsScreenDestination.route
    )

    val appPrefs: AppPreferences = koinInject()
    val showBottomNavLabels by appPrefs.showBottomNavLabels.collectAsState(initial = true)

    Scaffold(
        modifier = modifier,
        bottomBar = {
            if (showBottomBar) {
                NavigationBar(
                    containerColor = MaterialTheme.colorScheme.surface,
                    contentColor = MaterialTheme.colorScheme.onSurface
                ) {
                    screens.forEach { screen ->
                        val selected = currentDestination?.route?.contains(screen.route) == true
                        NavigationBarItem(
                            selected = selected,
                            onClick = {
                                if (selected) return@NavigationBarItem
                                navController.navigate(screen.route) {
                                    popUpTo(navController.graph.findStartDestination().id) {
                                        saveState = true
                                    }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            },
                            icon = {
                                Icon(
                                    painter = painterResource(screen.icon),
                                    contentDescription = stringResource(screen.labelRes)
                                )
                            },
                            label = if (showBottomNavLabels) {
                                {
                                    Text(
                                        text = stringResource(screen.labelRes),
                                        textAlign = TextAlign.Center,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        style = LocalTextStyle.current.copy(
                                            fontSize = 12.sp
                                        )
                                    )
                                }
                            } else null,
                            alwaysShowLabel = showBottomNavLabels,
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = MaterialTheme.colorScheme.primary,
                                selectedTextColor = MaterialTheme.colorScheme.primary,
                                indicatorColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)
                            )
                        )
                    }
                }
            }
        }
    ) { paddingValues ->
        Timber.d("$paddingValues")
        DestinationsNavHost(
            navGraph = NavGraphs.root,
            engine = engine,
            navController = navController,
            dependenciesContainerBuilder = {
                dependency(onRequestVpnPermission)
            }
        )
    }
}


package io.nekohasekai.sagernet.ui

import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.vectorResource
import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsBottomHeight
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.nekohasekai.sagernet.GroupOrder
import io.nekohasekai.sagernet.GroupType
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SubscriptionType
import io.nekohasekai.sagernet.compose.LinkOrContentTextField
import io.nekohasekai.sagernet.compose.PreferenceCategory
import io.nekohasekai.sagernet.compose.SimpleIconButton
import io.nekohasekai.sagernet.compose.TextButton
import io.nekohasekai.sagernet.compose.UIntegerTextField
import io.nekohasekai.sagernet.compose.paddingExceptBottom
import io.nekohasekai.sagernet.compose.theme.AppTheme
import io.nekohasekai.sagernet.database.ProfileManager
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.ktx.USER_AGENT
import io.nekohasekai.sagernet.ktx.blankAsNull
import io.nekohasekai.sagernet.ktx.intListN
import io.nekohasekai.sagernet.ktx.contentOrUnset
import io.nekohasekai.sagernet.ui.configuration.ProfileSelectActivity
import me.zhanghai.compose.preference.ListPreference
import me.zhanghai.compose.preference.ListPreferenceType
import me.zhanghai.compose.preference.ProvidePreferenceLocals
import me.zhanghai.compose.preference.SwitchPreference
import me.zhanghai.compose.preference.TextFieldPreference

class GroupSettingsActivity : ComposeActivity() {

    companion object {
        const val EXTRA_GROUP_ID = "id"
    }

    private val viewModel by viewModels<GroupSettingsActivityViewModel>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val editingId = intent.getLongExtra(EXTRA_GROUP_ID, 0L)
        viewModel.initialize(editingId)

        setContent {
            val isDirty by viewModel.isDirty.collectAsStateWithLifecycle()
            var showBackAlert by remember { mutableStateOf(false) }
            BackHandler(enabled = isDirty) {
                showBackAlert = true
            }

            val windowInsets = WindowInsets.safeDrawing
            val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior()
            val scrollState = rememberScrollState()

            AppTheme {
                Scaffold(
                    modifier = Modifier
                        .fillMaxSize()
                        .nestedScroll(scrollBehavior.nestedScrollConnection),
                    topBar = {
                        TopAppBar(
                            title = { Text(stringResource(R.string.group_settings)) },
                            navigationIcon = {
                                SimpleIconButton(
                                    imageVector = ImageVector.vectorResource(R.drawable.close),
                                    contentDescription = stringResource(R.string.close),
                                ) {
                                    onBackPressedDispatcher.onBackPressed()
                                }
                            },
                            actions = {
                                SimpleIconButton(
                                    imageVector = ImageVector.vectorResource(R.drawable.delete),
                                    contentDescription = stringResource(R.string.delete),
                                ) {
                                    if (viewModel.isNew) {
                                        finish()
                                    } else MaterialAlertDialogBuilder(this@GroupSettingsActivity)
                                        .setTitle(R.string.delete_group_prompt)
                                        .setPositiveButton(android.R.string.ok) { _, _ ->
                                            viewModel.delete()
                                            finish()
                                        }
                                        .setNegativeButton(android.R.string.cancel, null)
                                        .show()
                                }
                                SimpleIconButton(
                                    imageVector = ImageVector.vectorResource(R.drawable.done),
                                    contentDescription = stringResource(R.string.apply),
                                    onClick = ::saveAndExit,
                                )
                            },
                            windowInsets = windowInsets.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
                            scrollBehavior = scrollBehavior,
                        )
                    }
                ) { innerPadding ->
                    Column(
                        modifier = Modifier
                            .paddingExceptBottom(innerPadding)
                            .verticalScroll(scrollState)
                    ) {
                        GroupSettings()

                        Spacer(modifier = Modifier.windowInsetsBottomHeight(WindowInsets.navigationBars))
                    }
                }

                if (showBackAlert) AlertDialog(
                    onDismissRequest = { showBackAlert = false },
                    confirmButton = {
                        TextButton(stringResource(android.R.string.ok)) {
                            saveAndExit()
                        }
                    },
                    dismissButton = {
                        TextButton(stringResource(R.string.no)) {
                            finish()
                        }
                    },
                    icon = { Icon(ImageVector.vectorResource(R.drawable.question_mark), null) },
                    title = { Text(stringResource(R.string.unsaved_changes_prompt)) },
                )
            }
        }

    }

    @Composable
    private fun GroupSettings() {
        val uiState by viewModel.uiState.collectAsState()
        ProvidePreferenceLocals {
            TextFieldPreference(
                value = uiState.name,
                onValueChange = { viewModel.setName(it) },
                title = { Text(stringResource(R.string.group_name)) },
                textToValue = { it },
                icon = { Icon(ImageVector.vectorResource(R.drawable.emoji_symbols), null) },
                summary = { Text(LocalContext.current.contentOrUnset(uiState.name)) },
                valueToText = { it },
            )

            fun groupType(type: Int) = when (type) {
                GroupType.BASIC -> R.string.group_basic
                GroupType.SUBSCRIPTION -> R.string.subscription
                else -> error("impossible")
            }
            ListPreference(
                value = uiState.type,
                onValueChange = { viewModel.setType(it) },
                values = intListN(2),
                title = { Text(stringResource(R.string.group_type)) },
                icon = { Icon(ImageVector.vectorResource(R.drawable.layers), null) },
                summary = { Text(stringResource(groupType(uiState.type))) },
                type = ListPreferenceType.DROPDOWN_MENU,
                valueToText = { AnnotatedString(getString(groupType(it))) },
            )

            fun groupOrder(order: Int) = when (order) {
                GroupOrder.ORIGIN -> R.string.group_order_origin
                GroupOrder.BY_NAME -> R.string.group_order_by_name
                GroupOrder.BY_DELAY -> R.string.group_order_by_delay
                else -> error("impossible")
            }
            ListPreference(
                value = uiState.order,
                onValueChange = { viewModel.setOrder(it) },
                values = intListN(3),
                title = { Text(stringResource(R.string.group_order)) },
                icon = { Icon(ImageVector.vectorResource(R.drawable.low_priority), null) },
                summary = { Text(stringResource(groupOrder(uiState.order))) },
                type = ListPreferenceType.DROPDOWN_MENU,
                valueToText = { AnnotatedString(getString(groupOrder(it))) },
            )

            PreferenceCategory(text = { Text(stringResource(R.string.proxy_chain)) })
            fun chainName(id: Long) = SagerDatabase.proxyDao.getById(id)?.displayName()
            ListPreference(
                value = uiState.frontProxy,
                onValueChange = {
                    if (it == -1L) {
                        viewModel.setFrontProxy(it)
                    } else {
                        selectProfileForAddFront.launch(
                            Intent(this, ProfileSelectActivity::class.java)
                                .putExtra(ProfileSelectActivity.EXTRA_SELECTED, uiState.frontProxy)
                        )
                    }
                },
                values = listOf(-1L, 0L),
                title = { Text(stringResource(R.string.front_proxy)) },
                icon = { Icon(ImageVector.vectorResource(R.drawable.low_priority), null) },
                summary = {
                    val text = chainName(uiState.frontProxy)
                        ?: stringResource(R.string.not_set)
                    Text(text)
                },
                type = ListPreferenceType.DROPDOWN_MENU,
                valueToText = {
                    val id = if (it == -1L) {
                        R.string.ssh_auth_type_none
                    } else {
                        R.string.route_profile
                    }
                    AnnotatedString(getString(id))
                },
            )
            ListPreference(
                value = uiState.landingProxy,
                onValueChange = {
                    if (it == -1L) {
                        viewModel.setLandingProxy(it)
                    } else {
                        selectProfileForAddLanding.launch(
                            Intent(this, ProfileSelectActivity::class.java)
                                .putExtra(
                                    ProfileSelectActivity.EXTRA_SELECTED,
                                    uiState.landingProxy,
                                )
                        )
                    }
                },
                values = listOf(-1L, 0L),
                title = { Text(stringResource(R.string.landing_proxy)) },
                icon = { Icon(ImageVector.vectorResource(R.drawable.public_icon), null) },
                summary = {
                    val text = chainName(uiState.landingProxy)
                        ?: stringResource(R.string.not_set)
                    Text(text)
                },
                type = ListPreferenceType.DROPDOWN_MENU,
                valueToText = {
                    val id = if (it == -1L) {
                        R.string.ssh_auth_type_none
                    } else {
                        R.string.route_profile
                    }
                    AnnotatedString(getString(id))
                },
            )

            if (uiState.type == GroupType.SUBSCRIPTION) {
                PreferenceCategory(text = { Text(stringResource(R.string.subscription_settings)) })
                fun subType(type: Int) = when (type) {
                    SubscriptionType.RAW -> R.string.raw
                    SubscriptionType.OOCv1 -> R.string.oocv1
                    SubscriptionType.SIP008 -> R.string.sip008
                    else -> error("impossible")
                }
                ListPreference(
                    value = uiState.subscriptionType,
                    onValueChange = { viewModel.setSubscriptionType(it) },
                    values = intListN(3),
                    title = { Text(stringResource(R.string.subscription_type)) },
                    icon = { Icon(ImageVector.vectorResource(R.drawable.nfc), null) },
                    summary = { Text(stringResource(subType(uiState.subscriptionType))) },
                    type = ListPreferenceType.DROPDOWN_MENU,
                    valueToText = { AnnotatedString(getString(subType(it))) },
                )

                TextFieldPreference(
                    value = uiState.subscriptionLink,
                    onValueChange = { viewModel.setSubscriptionLink(it) },
                    title = { Text(stringResource(R.string.group_subscription_link)) },
                    textToValue = { it },
                    icon = { Icon(ImageVector.vectorResource(R.drawable.link), null) },
                    summary = { Text(LocalContext.current.contentOrUnset(uiState.subscriptionLink)) },
                    valueToText = { it },
                    textField = { value, onValueChange, onOk ->
                        LinkOrContentTextField(value, onValueChange, onOk)
                    },
                )
                val isOOCv1 = uiState.subscriptionType == SubscriptionType.OOCv1
                if (isOOCv1) TextFieldPreference(
                    value = uiState.subscriptionToken,
                    onValueChange = { viewModel.setSubscriptionToken(it) },
                    title = { Text(stringResource(R.string.ooc_subscription_token)) },
                    textToValue = { it },
                    icon = { Icon(ImageVector.vectorResource(R.drawable.vpn_key), null) },
                    summary = { Text(LocalContext.current.contentOrUnset(uiState.subscriptionToken)) },
                    valueToText = { it },
                )

                SwitchPreference(
                    value = uiState.subscriptionForceResolve,
                    onValueChange = { viewModel.setSubscriptionForceResolve(it) },
                    title = { Text(stringResource(R.string.force_resolve)) },
                    icon = { Icon(ImageVector.vectorResource(R.drawable.manage_search), null) },
                    summary = { Text(stringResource(R.string.force_resolve_sum)) },
                )
                SwitchPreference(
                    value = uiState.subscriptionDeduplication,
                    onValueChange = { viewModel.setSubscriptionDeduplication(it) },
                    title = { Text(stringResource(R.string.deduplication)) },
                    icon = { Icon(ImageVector.vectorResource(R.drawable.import_contacts), null) },
                    summary = { Text(stringResource(R.string.deduplication_sum)) },
                )
                TextFieldPreference(
                    value = uiState.subscriptionFilterNotRegex,
                    onValueChange = { viewModel.setSubscriptionFilterNotRegex(it) },
                    title = { Text(stringResource(R.string.filter_regex)) },
                    textToValue = { it },
                    icon = { Icon(ImageVector.vectorResource(R.drawable.delete_sweep), null) },
                    summary = { Text(LocalContext.current.contentOrUnset(uiState.subscriptionFilterNotRegex)) },
                    valueToText = { it },
                )

                PreferenceCategory(text = { Text(stringResource(R.string.update_settings)) })
                SwitchPreference(
                    value = uiState.subscriptionUpdateWhenConnectedOnly,
                    onValueChange = { viewModel.setSubscriptionUpdateWhenConnectedOnly(it) },
                    title = { Text(stringResource(R.string.update_when_connected_only)) },
                    icon = { Icon(ImageVector.vectorResource(R.drawable.security), null) },
                    summary = { Text(stringResource(R.string.update_when_connected_only_sum)) },
                )
                TextFieldPreference(
                    value = uiState.subscriptionUserAgent,
                    onValueChange = { viewModel.setSubscriptionUserAgent(it) },
                    title = { Text(stringResource(R.string.subscription_user_agent)) },
                    textToValue = { it },
                    icon = { Icon(ImageVector.vectorResource(R.drawable.grid_3x3), null) },
                    summary = {
                        val text = uiState.subscriptionUserAgent.blankAsNull() ?: USER_AGENT
                        Text(text)
                    },
                    valueToText = { it },
                )
                SwitchPreference(
                    value = uiState.subscriptionAutoUpdate,
                    onValueChange = { viewModel.setSubscriptionAutoUpdate(it) },
                    title = { Text(stringResource(R.string.auto_update)) },
                    icon = { Icon(ImageVector.vectorResource(R.drawable.flip_camera_android), null) },
                )
                TextFieldPreference(
                    value = uiState.subscriptionUpdateDelay,
                    onValueChange = { viewModel.setSubscriptionUpdateDelay(it) },
                    title = { Text(stringResource(R.string.auto_update_delay)) },
                    textToValue = { it.toIntOrNull() ?: 1440 },
                    icon = { Icon(ImageVector.vectorResource(R.drawable.grid_3x3), null) },
                    summary = { Text(uiState.subscriptionUpdateDelay.toString()) },
                    textField = { value, onValueChange, onOk ->
                        UIntegerTextField(value, onValueChange, onOk)
                    },
                )
            }
        }
    }

    private fun saveAndExit() {
        viewModel.save()
        setResult(RESULT_OK)
        finish()
    }

    private val selectProfileForAddFront = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        if (it.resultCode == RESULT_OK) {
            val profile = ProfileManager.getProfile(
                it.data!!.getLongExtra(ProfileSelectActivity.EXTRA_PROFILE_ID, 0)
            ) ?: return@registerForActivityResult
            viewModel.setFrontProxy(profile.id)
        }
    }

    private val selectProfileForAddLanding = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        if (it.resultCode == RESULT_OK) {
            val profile = ProfileManager.getProfile(
                it.data!!.getLongExtra(ProfileSelectActivity.EXTRA_PROFILE_ID, 0)
            ) ?: return@registerForActivityResult
            viewModel.setLandingProxy(profile.id)
        }
    }

}
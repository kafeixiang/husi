package fr.husi.ui

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextRange
import fr.husi.compose.IconMaskColors
import fr.husi.compose.MaskedIcon
import fr.husi.compose.SimpleIconButton
import fr.husi.compose.material3.Text
import fr.husi.ktx.contentOrUnset
import fr.husi.ktx.listByLineOrComma
import fr.husi.resources.Res
import fr.husi.resources.folder_open
import fr.husi.resources.legend_toggle
import fr.husi.resources.process
import fr.husi.resources.select_file
import io.github.vinceglb.filekit.absolutePath
import io.github.vinceglb.filekit.dialogs.FileKitMode
import io.github.vinceglb.filekit.dialogs.compose.rememberFilePickerLauncher
import me.zhanghai.compose.preference.TextFieldPreference
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.resources.vectorResource

@Composable
internal actual fun AppSelectPreference(
    packages: Set<String>,
    onSelectApps: (Set<String>) -> Unit,
) {
    val content = packages.joinToString("\n")
    TextFieldPreference(
        value = content,
        onValueChange = { text ->
            onSelectApps(text.listByLineOrComma().toSet())
        },
        title = { Text(stringResource(Res.string.process)) },
        icon = {
            MaskedIcon(
                resource = Res.drawable.legend_toggle,
                color = IconMaskColors.IconLavender,
            )
        },
        summary = { Text(contentOrUnset(content)) },
        textToValue = { it },
        valueToText = { it },
        textField = { value, onValueChange, onOk ->
            val filePicker = rememberFilePickerLauncher(
                mode = FileKitMode.Multiple(),
            ) { files ->
                if (files == null) return@rememberFilePickerLauncher
                val selectedPaths = files.joinToString("\n") { it.absolutePath() }
                val text = listOf(value.text, selectedPaths)
                    .filter { it.isNotEmpty() }
                    .joinToString("\n")
                onValueChange(value.copy(text = text, selection = TextRange(text.length)))
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = value,
                    onValueChange = onValueChange,
                    modifier = Modifier.weight(1f),
                    keyboardActions = KeyboardActions { onOk() },
                    singleLine = false,
                )
                SimpleIconButton(
                    imageVector = vectorResource(Res.drawable.folder_open),
                    contentDescription = stringResource(Res.string.select_file),
                    onClick = filePicker::launch,
                )
            }
        },
    )
}

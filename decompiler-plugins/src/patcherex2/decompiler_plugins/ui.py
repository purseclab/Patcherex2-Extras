import os
import subprocess

from libbs.ui.qt_objects import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    Qt,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)
from libbs.ui.version import ui_version

if ui_version == "PySide6":
    from PySide6.QtWidgets import QTextEdit
else:
    from PyQt5.QtWidgets import QTextEdit

import logging

import patcherex2

logging.getLogger("patcherex2").setLevel(logging.INFO)


class ControlPanel(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.main_layout = QVBoxLayout()

        self.add_options()
        self.add_patch_list()
        self.add_patch_script_editor()
        self.add_bottom_buttons()

        self.setLayout(self.main_layout)

    def add_options(self):
        options_layout = QGridLayout()
        options_group = QGroupBox("Options")
        options_group.setLayout(options_layout)

        # Automatically find unused space checkbox
        unused_space_checkbox = QCheckBox("Reuse Unused Functions")
        unused_space_checkbox.setToolTip(
            "Automatically find unused functions and mark them as free space."
        )
        unused_space_checkbox.setChecked(self.controller.find_unused_space)
        unused_space_checkbox.stateChanged.connect(self.toggle_reuse_unused_funcs)
        options_layout.addWidget(unused_space_checkbox, 0, 0)

        # Add unused space button
        unused_space_button = QPushButton("Add Unused Space Manually")
        unused_space_button.clicked.connect(self.add_unused_space)
        options_layout.addWidget(unused_space_button, 1, 0)

        self.main_layout.addWidget(options_group)

    def add_patch_list(self):
        patch_table = QTableWidget()
        patch_table.setColumnCount(3)
        patch_table.setHorizontalHeaderLabels(["Patch Type", "Arguments", "Actions"])
        patch_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents
        )
        patch_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        patch_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeToContents
        )
        patch_table.verticalHeader().setVisible(False)
        patch_table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        patch_group = QGroupBox("Patches")
        patch_layout = QVBoxLayout()
        patch_group.setLayout(patch_layout)
        patch_layout.addWidget(patch_table)

        self.main_layout.addWidget(patch_group)

        self.patch_table = patch_table

        for patch in self.controller.patches:
            self.add_patch_list_row(patch[0], patch[1])

    def add_patch_list_row(self, patch_type, patch_args):
        self.patch_table.insertRow(self.patch_table.rowCount())
        self.patch_table.setCellWidget(
            self.patch_table.rowCount() - 1, 0, QLabel(patch_type)
        )
        arg_str = ", ".join([f"{k}={v}" for k, v in patch_args.items()])
        self.patch_table.setCellWidget(
            self.patch_table.rowCount() - 1, 1, QLabel(arg_str)
        )
        remove_button = QPushButton("Remove")
        remove_button.clicked.connect(self.remove_patch)
        self.patch_table.setCellWidget(
            self.patch_table.rowCount() - 1, 2, remove_button
        )

    def remove_patch(self):
        button = self.sender()
        row = self.patch_table.indexAt(button.pos()).row()
        self.patch_table.removeRow(row)
        self.controller.patches.pop(row)

    def add_patch_script_editor(self):
        script_editor_layout = QVBoxLayout()
        script_editor_group = QGroupBox("Patch Script Editor")
        script_editor_group.setLayout(script_editor_layout)

        script_editor = QTextEdit()
        script_editor_layout.addWidget(script_editor)

        self.main_layout.addWidget(script_editor_group)

        self.script_editor = script_editor

    def add_bottom_buttons(self):
        bottom_layout = QHBoxLayout()
        add_patch = QPushButton("Add a New Patch")
        add_patch.clicked.connect(self.add_patch)
        regen_script = QPushButton("Regenerate Patch Script")
        regen_script.clicked.connect(self.regen_patch_script)
        patch_binary = QPushButton("Patch Binary")
        patch_binary.clicked.connect(self.patch_binary)

        bottom_layout.addWidget(add_patch)
        bottom_layout.addWidget(regen_script)
        bottom_layout.addWidget(patch_binary)

        self.main_layout.addLayout(bottom_layout)

    def regen_patch_script(self):
        self.script_editor.setText(self.script_gen())

    def toggle_reuse_unused_funcs(self):
        self.controller.find_unused_space = not self.controller.find_unused_space

    def add_unused_space(self):
        dialog = AddUnusedSpaceDialog(self.controller)
        dialog.exec_()
        self.update()

    def script_gen(self):
        # TODO: messy code please help
        # NOTE: do we care about arbitrary code execution at all?
        binary_path = self.controller.deci.binary_path

        script = "from patcherex2 import *\n"
        if self.controller.target == "auto":
            script += f"p = Patcherex('{binary_path}')\n"
        else:
            script += f"from patcherex2.targets import {self.controller.target}\n"
            script += (
                f"p = Patcherex('{binary_path}', target_cls={self.controller.target})\n"
            )

        for address, size in self.controller.manually_added_unused_space:
            script += f"p.allocation_manager.add_free_space({address}, {size}, 'RX')\n"

        if self.controller.find_unused_space:
            script += "for func in p.binary_analyzer.get_unused_funcs():\n"
            script += "    p.allocation_manager.add_free_space(func['addr'], func['size'], 'RX')\n"

        for patch in self.controller.patches:
            script += (
                f"p.patches.append({patch[0]}({', '.join(map(repr, patch[1]))}))\n\n"
            )

        script += "p.apply_patches()\n"
        script += f"p.save_binary('{binary_path + '-patched'}')\n"

        return script

    def patch_binary(self):
        try:
            binary_path = self.controller.deci.binary_path
            script = self.patch_script_editor.toPlainText()

            with open(binary_path + "_generated_patch.py", "w") as f:
                f.write(script)

            # run the script, pipe the output to the log widget
            subprocess.run(["python3", binary_path + "_generated_patch.py"])
        except Exception as e:
            logging.getLogger("patcherex2").error(e)
            MessageDialog(self.controller, "An error occurred while patching.").exec()
            return
        MessageDialog(self.controller, "Binary patched!").exec()
        dialog = LoadBinaryDialog()
        if dialog.exec() == QDialog.Accepted:
            # FIXME we need this feature but this is definitely not the right way to do it
            os.system(f"angr-management {binary_path}-patched &")

    def add_patch(self):
        dialog = PatchSelector()
        if dialog.exec() != QDialog.Accepted:
            return

        patch_type = dialog.get_value()
        dialog = PatchCreateDialog(patch_type)
        if dialog.exec() != QDialog.Accepted:
            return
        patch_args = dialog.get_values()

        self.add_patch_list_row(patch_type, patch_args)
        self.controller.patches.append((patch_type, patch_args))


class PatchCreateDialog(QDialog):
    def __init__(self, patch_type: str):
        super().__init__()

        self.setWindowTitle(f"Create a new {patch_type} patch - Patcherex2")
        self.main_layout = QVBoxLayout()
        # TODO: check Patch __init__ signature and create input fields accordingly
        if patch_type == "ModifyDataPatch":
            self.add_input("addr", "int")
            self.add_input("new_bytes", "bytes")

        self.confirm_button = QPushButton("Confirm")
        self.confirm_button.clicked.connect(self.accept)
        self.main_layout.addWidget(self.confirm_button)

        self.setLayout(self.main_layout)

    def get_values(self):
        values = {}
        for i in range(self.main_layout.count()):
            layout = self.main_layout.itemAt(i)
            if isinstance(layout, QHBoxLayout):
                input_ = layout.itemAt(1).widget()
                name = input_.objectName()
                if isinstance(input_, QLineEdit):
                    values[name] = int(input_.text(), 0)
                elif isinstance(input_, QTextEdit):
                    values[name] = input_.toPlainText()
        return values

    def add_input(self, name, type_):
        layout = QHBoxLayout()
        if type_ == "int":
            layout.addWidget(QLabel(f"{name}:"))
            input_ = QLineEdit()
            input_.setObjectName(name)
            layout.addWidget(input_)
        elif type_ == "str":
            layout.addWidget(QLabel(f"{name}:"))
            input_ = QTextEdit()
            layout.addWidget(input_)
        elif type_ == "bytes":
            layout.addWidget(QLabel(f"{name}:"))
            input_ = QTextEdit()
            layout.addWidget(input_)
        else:
            layout.addWidget(QLabel(f"{name}:"))
            input_ = QLineEdit()
            layout.addWidget(input_)

        self.main_layout.addLayout(layout)


class ConfigurePatcherex2Dialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller

        self.setWindowTitle("Configurations - Patcherex2")
        self.setMinimumSize(300, 250)
        self.main_layout = QVBoxLayout()
        self.main_layout.setAlignment(Qt.AlignCenter)

        target_selection_text = QLabel(self)
        target_selection_text.setText("Select Target:")
        self.main_layout.addWidget(target_selection_text)

        target_selection_dropdown = QComboBox(self)
        target_selection_dropdown.addItem("auto")
        for target_name in patcherex2.targets.__all__:
            if target_name == "Target":
                continue
            target_selection_dropdown.addItem(target_name)
        target_selection_dropdown.setCurrentText(self.controller.target)
        self.main_layout.addWidget(target_selection_dropdown)

        save_button = QPushButton(self)
        save_button.setText("Save")
        save_button.clicked.connect(self.on_save_clicked)
        self.main_layout.addWidget(save_button)

        self.setLayout(self.main_layout)

    def on_save_clicked(self):
        self.controller.target = (
            self.sender().parent().findChild(QComboBox).currentText()
        )
        self.close()


class PatchSelector(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Add a New Patch - Patcherex2")

        layout = QVBoxLayout()

        instructions = QLabel("Which type of patch would you like to add?")
        layout.addWidget(instructions)

        self.patch_selector = QComboBox()
        for patch in patcherex2.patches.__all__:
            self.patch_selector.addItem(patch)
        layout.addWidget(self.patch_selector)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

    def get_value(self):
        return self.patch_selector.currentText()


class LoadBinaryDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Binary Patched - Patcherex2")

        layout = QVBoxLayout()

        instructions = QLabel("Would you like to load the patched binary?")
        layout.addWidget(instructions)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)


class AddUnusedSpaceDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Patcherex2")
        layout = QVBoxLayout()

        label = QLabel("Please enter the address and size of the unused space.")
        layout.addWidget(label)

        address_label = QLabel("Address:")
        self.address_input = QLineEdit()
        layout.addWidget(address_label)
        layout.addWidget(self.address_input)

        size_label = QLabel("Size:")
        self.size_input = QLineEdit()
        layout.addWidget(size_label)
        layout.addWidget(self.size_input)

        confirm_button = QPushButton("Confirm")
        confirm_button.clicked.connect(self.confirm_selection)
        layout.addWidget(confirm_button)

        self.setLayout(layout)

    def confirm_selection(self):
        address = int(self.address_input.text(), 0)
        size = int(self.size_input.text(), 0)
        self.controller.manually_added_unused_space.append((address, size))
        self.close()


class MessageDialog(QDialog):
    def __init__(self, controller, message, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Patcherex2")
        layout = QVBoxLayout()
        message = QLabel(message)
        confirm_button = QPushButton("Ok")
        confirm_button.clicked.connect(self.confirm_selection)

        layout.addWidget(message)
        layout.addWidget(confirm_button)
        self.setLayout(layout)

    def confirm_selection(self):
        self.close()

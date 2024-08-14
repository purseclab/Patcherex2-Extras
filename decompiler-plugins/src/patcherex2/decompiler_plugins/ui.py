import os
import re
import select  # noqa: F401

import patcherex2

# from libbs.ui.qt_objects import (
#     QAbstractItemView,
#     QCheckBox,
#     QComboBox,
#     QDialog,
#     QDialogButtonBox,
#     QGridLayout,
#     QGroupBox,
#     QHBoxLayout,
#     QHeaderView,
#     QLabel,
#     QLineEdit,
#     QMessageBox,
#     QPushButton,
#     QTableWidget,
#     QVBoxLayout,
#     QWidget,
# )
from libbs.ui.version import ui_version
from patcherex2 import *

from .controller import Patcherex2Controller, UIPatch
from .decompiler_specific.deci_extras import *

if ui_version == "PySide6":
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import (
        QAbstractItemView,
        QApplication,
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
        QMessageBox,
        QProgressDialog,
        QPushButton,
        QTableWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
else:
    from PyQt5.QtGui import QFont
    from PyQt5.QtWidgets import (
        QAbstractItemView,
        QApplication,
        QCheckBox,
        QComboBox,
        QDialog,
        QDialogButtonBox,
        QFont,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMessageBox,
        QProgressDialog,
        QPushButton,
        QTableWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )

import logging

# os.environ["PYTHONBREAKPOINT"] = "remote_pdb.set_trace"
# os.environ["REMOTE_PDB_PORT"] = "1234"


logging.getLogger("patcherex2").setLevel(logging.INFO)


class ControlPanel(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller: Patcherex2Controller = controller
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

        target_widget = QWidget()
        selectTargetLayout = QHBoxLayout(target_widget)

        target_selection_text = QLabel("Target:")

        selectTargetLayout.addWidget(target_selection_text)

        target_selection_dropdown = QComboBox(self)
        target_selection_dropdown.addItem("auto")
        for target_name in patcherex2.targets.__all__:
            if target_name == "Target":
                continue
            target_selection_dropdown.addItem(target_name)
        target_selection_dropdown.setCurrentText(self.controller.target)
        target_selection_dropdown.currentTextChanged.connect(self.set_target)
        selectTargetLayout.addWidget(target_selection_dropdown)
        options_layout.addWidget(target_widget, 0, 0)

        # Automatically find unused space checkbox
        unused_space_checkbox = QCheckBox("Reuse Unused Functions")
        unused_space_checkbox.setToolTip(
            "Automatically find unused functions and mark them as free space."
        )
        unused_space_checkbox.setChecked(self.controller.find_unused_space)
        unused_space_checkbox.stateChanged.connect(self.toggle_reuse_unused_funcs)
        options_layout.addWidget(unused_space_checkbox, 1, 0)

        # Add unused space button
        unused_space_button = QPushButton("Add Unused Space Manually")
        unused_space_button.clicked.connect(self.add_unused_space)
        options_layout.addWidget(unused_space_button, 2, 0)

        self.main_layout.addWidget(options_group)

    def add_patch_list(self):
        patch_table = QTableWidget()
        patch_table.setColumnCount(6)
        patch_table.setHorizontalHeaderLabels(
            ["Patch Type", "Location", "", "", "", ""]
        )
        patch_table.verticalHeader().setVisible(False)
        patch_table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        patch_group = QGroupBox("Patches")
        patch_layout = QVBoxLayout()
        patch_group.setLayout(patch_layout)
        patch_layout.addWidget(patch_table)

        self.main_layout.addWidget(patch_group)

        patch_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        patch_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeToContents
        )
        patch_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        patch_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        patch_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        patch_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)

        self.patch_table = patch_table

        for patch in self.controller.patches:
            self.add_patch_list_row(patch.patch_type, patch.args)

    def add_patch_list_row(self, patch_type, patch_args):
        self.patch_table.insertRow(self.patch_table.rowCount())
        self.patch_table.setCellWidget(
            self.patch_table.rowCount() - 1, 0, QLabel(patch_type)
        )

        loc = patch_args.get("addr", patch_args.get("addr_or_name", ""))
        if isinstance(loc, int):
            loc = hex(denormalize_addr(self.controller.deci, loc))
        self.patch_table.setCellWidget(self.patch_table.rowCount() - 1, 1, QLabel(loc))
        remove_button = QPushButton("Remove")
        remove_button.clicked.connect(self.remove_patch)
        edit_button = QPushButton("Edit")
        edit_button.clicked.connect(self.edit_patch)
        up_button = QPushButton("↑")
        up_button.clicked.connect(self.move_patch_up)
        down_button = QPushButton("↓")
        down_button.clicked.connect(self.move_patch_down)

        self.patch_table.setCellWidget(self.patch_table.rowCount() - 1, 2, edit_button)
        self.patch_table.setCellWidget(
            self.patch_table.rowCount() - 1, 3, remove_button
        )
        self.patch_table.setCellWidget(self.patch_table.rowCount() - 1, 4, up_button)
        self.patch_table.setCellWidget(self.patch_table.rowCount() - 1, 5, down_button)

        self.patch_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        self.patch_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeToContents
        )

    def move_patch_up(self):
        button = self.sender()
        row = self.patch_table.indexAt(button.pos()).row()
        if row == 0:
            return
        tmp = self.patch_table.cellWidget(row, 0).text()
        self.patch_table.cellWidget(row, 0).setText(
            self.patch_table.cellWidget(row - 1, 0).text()
        )
        self.patch_table.cellWidget(row - 1, 0).setText(tmp)
        tmp = self.patch_table.cellWidget(row, 1).text()
        self.patch_table.cellWidget(row, 1).setText(
            self.patch_table.cellWidget(row - 1, 1).text()
        )
        self.patch_table.cellWidget(row - 1, 1).setText(tmp)
        patch = self.controller.patches.pop(row)
        self.controller.patches.insert(row - 1, patch)

    def move_patch_down(self):
        button = self.sender()
        row = self.patch_table.indexAt(button.pos()).row()
        if row == self.patch_table.rowCount() - 1:
            return
        tmp = self.patch_table.cellWidget(row, 0).text()
        self.patch_table.cellWidget(row, 0).setText(
            self.patch_table.cellWidget(row + 1, 0).text()
        )
        self.patch_table.cellWidget(row + 1, 0).setText(tmp)
        tmp = self.patch_table.cellWidget(row, 1).text()
        self.patch_table.cellWidget(row, 1).setText(
            self.patch_table.cellWidget(row + 1, 1).text()
        )
        self.patch_table.cellWidget(row + 1, 1).setText(tmp)
        patch = self.controller.patches.pop(row)
        self.controller.patches.insert(row + 1, patch)

    def remove_patch(self):
        button = self.sender()
        row = self.patch_table.indexAt(button.pos()).row()
        self.patch_table.removeRow(row)
        self.controller.patches.pop(row)

    def edit_patch(self):
        # it should pop up a pre-filled PatchCreateDialog with the current values
        # and then update the patch in the controller and the table
        button = self.sender()
        row = self.patch_table.indexAt(button.pos()).row()
        patch_type = self.patch_table.cellWidget(row, 0).text()
        patch_args = self.controller.patches[row].args.copy()
        if "addr" in patch_args.keys():
            patch_args["addr"] = denormalize_addr(
                self.controller.deci, patch_args["addr"]
            )
        if "addr_or_name" in patch_args.keys() and isinstance(
            patch_args["addr_or_name"], int
        ):
            patch_args["addr_or_name"] = denormalize_addr(
                self.controller.deci, patch_args["addr_or_name"]
            )
        patch_args = {
            k: hex(v) if isinstance(v, int) else v for k, v in patch_args.items()
        }
        dialog = PatchCreateDialog(patch_type, patch_args)
        dialog.exec_()
        new_patch_args = dialog.get_values()
        if "addr" in patch_args.keys():
            patch_args["addr"] = normalize_addr(
                self.controller.deci, patch_args["addr"]
            )
        if "addr_or_name" in patch_args.keys() and isinstance(
            patch_args["addr_or_name"], int
        ):
            patch_args["addr_or_name"] = normalize_addr(
                self.controller.deci, patch_args["addr_or_name"]
            )
        self.controller.patches[row] = UIPatch(patch_type, new_patch_args)

        loc = new_patch_args.get("addr", new_patch_args.get("addr_or_name", ""))
        if isinstance(loc, int):
            loc = hex(denormalize_addr(self.controller.deci, loc))
        self.patch_table.cellWidget(row, 1).setText(loc)

    def add_patch_script_editor(self):
        script_editor_layout = QVBoxLayout()
        script_editor_group = QGroupBox("Patch Script Editor")
        script_editor_group.setLayout(script_editor_layout)

        script_editor = QTextEdit()
        font = script_editor.document().defaultFont()
        font.setFamily("Monospace")
        font.setStyleHint(QFont.StyleHint.Monospace)
        script_editor.document().setDefaultFont(font)
        script_editor.setPlaceholderText("Patch script will be generated here.")
        script_editor_layout.addWidget(script_editor)

        self.main_layout.addWidget(script_editor_group)

        self.script_editor = script_editor

    def add_bottom_buttons(self):
        bottom_layout = QHBoxLayout()
        add_patch = QPushButton("Add a New Patch")
        add_patch.clicked.connect(self.add_patch)
        regen_script = QPushButton("Regenerate Patch Script")
        regen_script.clicked.connect(self.regen_patch_script)
        reload_patches = QPushButton("Reload Patches From Script")
        reload_patches.clicked.connect(self.reload_from_script)
        patch_binary = QPushButton("Patch Binary")
        patch_binary.clicked.connect(self.patch_binary)

        bottom_layout.addWidget(add_patch)
        bottom_layout.addWidget(regen_script)
        bottom_layout.addWidget(reload_patches)
        bottom_layout.addWidget(patch_binary)

        self.main_layout.addLayout(bottom_layout)

    def regen_patch_script(self):
        self.script_editor.setPlainText(self.script_gen())

    def set_target(self):
        self.controller.target = self.sender().currentText()

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

        patcherex_args = [f"'{binary_path}'"]

        if self.controller.target != "auto":
            script += f"from patcherex2.targets import {self.controller.target}\n"
            patcherex_args.append(f"target_cls={self.controller.target}")

        if not isinstance(self.controller.deci, AngrInterface):
            if isinstance(self.controller.deci, GhidraDecompilerInterface):
                patcherex_args.append("target_opts={'binary_analyzer': 'ghidra'}")

        script += f"p = Patcherex({', '.join(patcherex_args)})\n"

        for address, size in self.controller.manually_added_unused_space:
            script += f"p.allocation_manager.add_free_space({address}, {size}, 'RX')\n"

        if self.controller.find_unused_space:
            script += "for func in p.binary_analyzer.get_unused_funcs():\n"
            script += "    p.allocation_manager.add_free_space(func['addr'], func['size'], 'RX')\n"

        for patch in self.controller.patches:
            script += f"p.patches.append({patch.patch_type}({', '.join([f'{k}={repr(v)}' for k, v in patch.args.items()])}))\n"

        script += "p.apply_patches()\n"
        script += "p.save_binary()\n"

        return script

    def reload_from_script(self):
        text = self.script_editor.toPlainText()

        pat = re.compile("p = Patcherex\([^)]*\)")
        text = pat.sub("", text)
        text = text.replace("p.patches", "patches")
        text = text.replace("p.apply_patches()", "")
        pat = re.compile("p\.save_binary\([^)]*\)")
        text = pat.sub("", text)

        patches = []
        exec(text)

        while self.patch_table.rowCount() > 0:
            self.patch_table.removeRow(0)
        self.controller.patches = []

        for patch in patches:
            args = {}
            if isinstance(patch, ModifyDataPatch):
                patch_name = "ModifyDataPatch"
                args["addr"] = patch.addr
                args["new_bytes"] = patch.new_bytes
            elif isinstance(patch, InsertDataPatch):
                patch_name = "InsertDataPatch"
                args["addr_or_name"] = patch.addr or patch.name
                args["data"] = patch.data
            elif isinstance(patch, RemoveDataPatch):
                patch_name = "RemoveDataPatch"
                args["addr"] = patch.addr
                args["size"] = patch.size
            elif isinstance(patch, ModifyInstructionPatch):
                patch_name = "ModifyInstructionPatch"
                args["addr"] = patch.addr
                args["instr"] = patch.instr
            elif isinstance(patch, InsertInstructionPatch):
                patch_name = "InsertInstructionPatch"
                args["addr_or_name"] = patch.addr or patch.name
                args["instr"] = patch.instr
            elif isinstance(patch, RemoveInstructionPatch):
                patch_name = "RemoveInstructionPatch"
                args["addr"] = patch.addr
                args["num_instr"] = patch.num_instr
            elif isinstance(patch, ModifyFunctionPatch):
                patch_name = "ModifyFunctionPatch"
                args["addr_or_name"] = patch.addr_or_name
                args["code"] = patch.code
            elif isinstance(patch, InsertFunctionPatch):
                patch_name = "InsertFunctionPatch"
                args["addr_or_name"] = patch.addr or patch.name
                args["code"] = patch.code
                args["prefunc"] = patch.prefunc
                args["postfunc"] = patch.postfunc
            self.controller.patches.append(UIPatch(patch_name, args))
            self.add_patch_list_row(patch_name, args)

    def patch_binary(self):
        progressdialog = QProgressDialog()
        progressdialog.setRange(0, 0)
        progressdialog.setWindowTitle("Patching...")
        progressdialog.setLabelText("Patching...")
        progressdialog.setCancelButton(None)
        progressdialog.show()
        QApplication.processEvents()

        try:
            binary_path = self.controller.deci.binary_path
            script = self.script_editor.toPlainText()

            exec(script)

        except Exception as e:
            logging.getLogger("patcherex2").error("Failed to patch binary", exc_info=1)
            progressdialog.hide()
            QMessageBox.critical(None, "Error", f"Failed to patch binary: {e}")
            return
        progressdialog.hide()
        QMessageBox.information(None, "Success", "Binary patched!")
        self.controller.patched_patches = self.controller.patches.copy()
        dialog = LoadBinaryDialog()
        if dialog.exec() == QDialog.Accepted:
            load_patched_binary(self.controller.deci, binary_path=binary_path)

    def add_patch(self):
        open_panel(self.controller.deci)
        addr = get_ctx_address(self.controller.deci)
        if addr is None:
            prefill = {}
        else:
            prefill = {"addr": hex(addr), "addr_or_name": hex(addr)}
        dialog = PatchSelector()
        if dialog.exec_() != QDialog.Accepted:
            return
        patch_type = dialog.get_value()
        dialog = PatchCreateDialog(patch_type, prefill)
        if dialog.exec_() != QDialog.Accepted:
            return
        patch_args = dialog.get_values()

        if "addr" in patch_args.keys():
            patch_args["addr"] = normalize_addr(
                self.controller.deci, patch_args["addr"]
            )
        if "addr_or_name" in patch_args.keys() and isinstance(
            patch_args["addr_or_name"], int
        ):
            patch_args["addr_or_name"] = normalize_addr(
                self.controller.deci, patch_args["addr_or_name"]
            )

        self.add_patch_list_row(patch_type, patch_args)
        self.controller.patches.append(UIPatch(patch_type, patch_args))


class PatchCreateDialog(QDialog):
    def __init__(self, patch_type: str, prefill_values=None):
        super().__init__()

        self.prefill_values = prefill_values or {}

        self.setWindowTitle(f"{patch_type} - Patcherex2")
        self.main_layout = QVBoxLayout()
        # TODO: check Patch __init__ signature using `inspect` and create input fields accordingly
        # but note that some params are optional, some are mutually exclusive, etc.
        if patch_type == "ModifyDataPatch":
            self.add_input("addr", "int")
            self.add_input("new_bytes", "bytes")
        elif patch_type == "InsertDataPatch":
            self.add_input("addr_or_name", "int | str")
            self.add_input("data", "bytes")
        elif patch_type == "RemoveDataPatch":
            self.add_input("addr", "int")
            self.add_input("size", "int")
        elif patch_type == "ModifyInstructionPatch":
            self.add_input("addr", "int")
            self.add_input("instr", "str")
        elif patch_type == "InsertInstructionPatch":
            self.add_input("addr_or_name", "int | str")
            self.add_input("instr", "str")
        elif patch_type == "RemoveInstructionPatch":
            self.add_input("addr", "int")
            self.add_input("num_instr", "int")
        elif patch_type == "ModifyFunctionPatch":
            self.add_input("addr_or_name", "int | str")
            self.add_input("code", "str")
        elif patch_type == "InsertFunctionPatch":
            self.add_input("addr_or_name", "int | str")
            self.add_input("code", "str")
            self.add_input("prefunc", "str | none")
            self.add_input("postfunc", "str | none")

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
                values[name] = input_.get_value()
        return values

    def add_input(self, name, type_):
        layout = QHBoxLayout()
        layout.addWidget(QLabel(f"{name}:"))
        if type_ == "int":
            input_ = AddressEdit(self.prefill_values.get(name, ""))
        elif type_ == "int | str":
            input_ = AddressOrNameEdit(self.prefill_values.get(name, ""))
        elif type_ == "str":
            input_ = CodeEdit(self.prefill_values.get(name, ""))
        elif type_ == "bytes":
            input_ = BytesEdit(self.prefill_values.get(name, b"").decode())
        elif type_ == "str | none":
            input_ = TextOrNoneEdit(self.prefill_values.get(name, ""))
        else:
            raise ValueError(f"Unknown input type: {type_}")

        input_.setObjectName(name)
        layout.addWidget(input_)

        self.main_layout.addLayout(layout)


class TextOrNoneEdit(QTextEdit):
    def __init__(self, arg):
        super().__init__(arg)
        font = self.document().defaultFont()
        font.setFamily("Monospace")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.document().setDefaultFont(font)

    def get_value(self):
        if self.toPlainText() == "":
            return None
        return self.toPlainText()


class CodeEdit(QTextEdit):
    def __init__(self, text: str):
        super().__init__()
        font = self.document().defaultFont()
        font.setFamily("Monospace")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.document().setDefaultFont(font)
        self.setPlainText(text)

    def get_value(self):
        return self.toPlainText()


class AddressOrNameEdit(QLineEdit):
    def __init__(self, arg):
        super().__init__(arg)
        font = self.font()
        font.setFamily("Monospace")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)

    def get_value(self):
        try:
            return int(self.text(), 0)
        except ValueError:
            return self.text()


class AddressEdit(QLineEdit):
    def __init__(self, arg):
        super().__init__(arg)
        font = self.font()
        font.setFamily("Monospace")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)

    def get_value(self):
        try:
            return int(self.text(), 0)
        except ValueError:
            return 0


class BytesEdit(QTextEdit):
    def __init__(self, text: str):
        super().__init__()
        font = self.document().defaultFont()
        font.setFamily("Monospace")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.document().setDefaultFont(font)
        self.setPlainText(text)

    def get_value(self):
        return self.toPlainText().encode()


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

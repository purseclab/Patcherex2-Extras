import os
import shlex
import subprocess

from libbs.ui.qt_objects import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QObject,
    QPushButton,
    QScrollArea,
    Qt,
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
from patcherex2 import (
    InsertDataPatch,
    InsertFunctionPatch,
    InsertInstructionPatch,
    ModifyDataPatch,
    ModifyFunctionPatch,
    ModifyInstructionPatch,
    ModifyRawBytesPatch,
    Patcherex,
    RemoveDataPatch,
    # RemoveFunctionPatch,
    RemoveInstructionPatch,
)

logging.getLogger("patcherex2").setLevel(logging.INFO)


class QTextEditHandler(logging.Handler):
    def __init__(self, text_edit):
        super().__init__()
        self.text_edit = text_edit

    def emit(self, record):
        log = self.format(record)
        self.text_edit.append(log)


class Patcherex2UIWorker(QObject):
    def __init__(self):
        QObject.__init__(self)

    def run(self):
        dialog = Patcherex2Dialog()
        dialog.exec_()


class Patcherex2Dialog(QDialog):
    def __init__(self, controller, parent):
        super().__init__(self, parent=parent)
        self.controller = controller
        self.setWindowTitle("test")


class ControlPanel(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.main_layout = QVBoxLayout()

        # Options
        options_label = QLabel()
        options_label.setText("Options:")
        self.main_layout.addWidget(options_label)

        # Automatically find unused space checkbox
        find_unused_space_checkbox = QCheckBox()
        find_unused_space_checkbox.setText("Automatically Find Unused Space")
        find_unused_space_checkbox.setChecked(self.controller.find_unused_space)
        find_unused_space_checkbox.stateChanged.connect(self.toggle_find_unused_space)
        self.main_layout.addWidget(find_unused_space_checkbox)

        # Add unused space button
        unused_space_button = QPushButton()
        unused_space_button.setText("Add Unused Space Manually")
        unused_space_button.clicked.connect(self.add_unused_space)
        self.main_layout.addWidget(unused_space_button)

        # Patches
        patches_label = QLabel()
        patches_label.setText("Added Patches:")
        self.main_layout.addWidget(patches_label)

        self.patch_layout = QVBoxLayout()
        self.patch_layout.setAlignment(Qt.AlignCenter)

        for i in self.controller.patches:
            self.add_patch(i)

        group_box = QGroupBox()
        group_box.setLayout(self.patch_layout)
        scroll_area = QScrollArea()
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        scroll_area.setWidget(group_box)
        scroll_area.setWidgetResizable(True)
        scroll_area.setFixedHeight(350)
        bottom_layout = QHBoxLayout()
        add_patch = QPushButton()
        add_patch.setText("Add a New Patch")
        add_patch.clicked.connect(self.add_patch)
        patch_binary = QPushButton()
        patch_binary.setText("Patch Binary")
        patch_binary.clicked.connect(self.patch_binary)
        bottom_layout.addWidget(add_patch)
        bottom_layout.addWidget(patch_binary)

        self.main_layout.addWidget(scroll_area)
        self.main_layout.addLayout(bottom_layout)

        self.setLayout(self.main_layout)

    def toggle_find_unused_space(self):
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
                f"p = Patcherex('{binary_path}', target={self.controller.target})\n"
            )

        for address, size in self.controller.manually_added_unused_space:
            script += f"p.allocation_manager.add_free_space({address}, {size}, 'RX')\n"

        if self.controller.find_unused_space:
            script += "for func in p.binary_analyzer.get_unused_funcs():\n"
            script += "    p.allocation_manager.add_free_space(func['addr'], func['size'], 'RX')\n"

        for patch in self.controller.patches:
            script += f"p.patches.append({patch.patch_name}({', '.join(map(repr, patch.patch_args))}))\n"

        script += "p.apply_patches()\n"
        script += f"p.save_binary('{binary_path + '-patched'}')\n"

        return script

    def patch_binary(self):
        # log_widget = QTextEdit()
        # log_widget.setReadOnly(True)
        # log_widget.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        # log_widget.setFixedHeight(200)
        # log_widget.setFixedWidth(800)
        # log_widget.setWindowTitle("Patcherex2 Log")
        # log_widget.show()

        # handler = QTextEditHandler(log_widget)
        # handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        # logging.getLogger("patcherex2").addHandler(handler)

        try:
            binary_path = self.controller.deci.binary_path
            script = self.script_gen()
            editor = PatchScriptEditor(script)
            if editor.exec() != QDialog.Accepted:
                return
            script = editor.get_script()
            with open(binary_path + "_generated_patch.py", "w") as f:
                f.write(script)

            # run the script, pipe the output to the log widget
            p = subprocess.run(
                ["python3", binary_path + "_generated_patch.py"],
                # stdout=subprocess.PIPE,
                # stderr=subprocess.STDOUT,
                # text=True,
                # check=True,
            )
            # log_widget.append(p.stdout)

            # if self.controller.target == "auto":
            #     p = Patcherex(binary_path)
            # else:
            #     p = Patcherex(
            #         binary_path,
            #         target=getattr(patcherex2.targets, self.controller.target),
            #     )
            # for address, size in self.controller.manually_added_unused_space:
            #     p.allocation_manager.add_free_space(address, size, "RX")
            # if self.controller.find_unused_space:
            #     for func in p.binary_analyzer.get_unused_funcs():
            #         p.allocation_manager.add_free_space(
            #             func["addr"], func["size"], "RX"
            #         )
            # p.patches = [i.patch for i in self.controller.patches]
            # p.apply_patches()
            # p.save_binary(binary_path + "-patched")
        except Exception as e:
            logging.getLogger("patcherex2").error(e)
            display_message(self.controller, "An error occurred while patching.")
            return
        display_message(
            self.controller,
            "Binary patched! A new file with '-patched' appended has been made. Load it to see the changes.",
        )
        dialog = LoadBinaryDialog()
        if dialog.exec() == QDialog.Accepted:
            # FIXME we need this feature but this is definitely not the right way to do it
            os.system(f"angr-management {binary_path}-patched")

    def add_patch(self):
        dialog = PatchSelector()
        if dialog.exec() != QDialog.Accepted:
            return

        patch_type = dialog.get_value()

        self.controller.new_patch_args = []

        # check patch args and generate ui components for them

        if patch_type == "ModifyRawBytesPatch":
            ask_for_address(self.controller)
            ask_for_bytes(self.controller)
            patch = ModifyRawBytesPatch(*self.controller.new_patch_args)

        elif patch_type == "ModifyDataPatch":
            ask_for_address(self.controller)
            ask_for_bytes(self.controller)
            patch = ModifyDataPatch(*self.controller.new_patch_args)

        elif patch_type == "InsertDataPatch":
            ask_for_address_or_name(self.controller)
            ask_for_bytes(self.controller)
            patch = InsertDataPatch(*self.controller.new_patch_args)

        elif patch_type == "RemoveDataPatch":
            ask_for_address(self.controller)
            ask_for_size(self.controller)
            patch = RemoveDataPatch(*self.controller.new_patch_args)

        elif patch_type == "ModifyFunctionPatch":
            ask_for_address_or_name(self.controller)
            ask_for_code(self.controller)
            patch = ModifyFunctionPatch(*self.controller.new_patch_args)

        elif patch_type == "InsertFunctionPatch":
            ask_for_address_or_name(self.controller)
            ask_for_code(self.controller)
            patch = InsertFunctionPatch(*self.controller.new_patch_args)

        elif patch_type == "RemoveFunctionPatch":
            display_message(self.controller, "Not Implemented")
            return

        elif patch_type == "ModifyInstructionPatch":
            ask_for_address(self.controller)
            ask_for_instructions(self.controller)
            patch = ModifyInstructionPatch(*self.controller.new_patch_args)

        elif patch_type == "InsertInstructionPatch":
            ask_for_address_or_name(self.controller)
            ask_for_instructions(self.controller)
            patch = InsertInstructionPatch(*self.controller.new_patch_args)

        elif patch_type == "RemoveInstructionPatch":
            ask_for_address(self.controller)
            ask_for_size(self.controller)
            patch = RemoveInstructionPatch(*self.controller.new_patch_args)

        ui_patch = UIPatch(
            self.controller,
            patch_type,
            patch,
            self.controller.new_patch_args,
            parent=self,
        )
        self.patch_layout.addWidget(ui_patch)
        self.controller.patches.append(ui_patch)
        self.update()


class UIPatch(QWidget):
    def __init__(self, controller, patch_name, patch, patch_args, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.controller = controller
        self.patch = patch
        self.patch_name = patch_name
        self.patch_args = patch_args
        self.main_layout = QHBoxLayout()
        name = QLabel()
        name.setText(patch_name)
        remove = QPushButton()
        remove.setText("Remove")
        remove.clicked.connect(self.remove_from_parent)
        view = QPushButton()
        view.setText("View")
        view.clicked.connect(self.view)

        self.main_layout.addWidget(name)
        self.main_layout.addWidget(view)
        self.main_layout.addWidget(remove)
        self.setLayout(self.main_layout)

    def view(self):
        patch_string = self.patch_name + "(" + self.patch_args.__repr__()[1:-1] + ")"
        self.controller.deci.print(patch_string)
        display_message(self.controller, patch_string)

    def remove_from_parent(self):
        self.controller.patches.remove(self)
        self.setParent(None)
        self.parent.update()


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


class PatchScriptEditor(QDialog):
    def __init__(self, text, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Patcherex2 Script Editor")
        layout = QVBoxLayout()
        self.editor = QTextEdit()
        self.editor.setPlainText(text)
        layout.addWidget(self.editor)
        self.setLayout(layout)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def get_script(self):
        return self.editor.toPlainText()


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


class MultiLineDialog(QDialog):
    def __init__(self, controller, query, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Patcherex2")
        layout = QVBoxLayout()
        query = QLabel(query)
        self.text_input = QTextEdit()
        confirm_button = QPushButton("Confirm")
        confirm_button.clicked.connect(self.confirm_selection)

        layout.addWidget(query)
        layout.addWidget(self.text_input)
        layout.addWidget(confirm_button)
        self.setLayout(layout)

    def confirm_selection(self):
        self.controller.new_patch_args.append(self.text_input.toPlainText())
        self.close()


class SingleLineDialog(QDialog):
    def __init__(self, controller, query, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Patcherex2")
        layout = QVBoxLayout()
        query = QLabel(query)
        self.text_input = QLineEdit()
        confirm_button = QPushButton("Confirm")
        confirm_button.clicked.connect(self.confirm_selection)

        layout.addWidget(query)
        layout.addWidget(self.text_input)
        layout.addWidget(confirm_button)
        self.setLayout(layout)

    def confirm_selection(self):
        self.controller.new_patch_args.append(self.text_input.text())
        self.close()


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


def ask_for_instructions(controller):
    dialog = MultiLineDialog(controller, "Instructions for the patch?")
    dialog.exec_()


def ask_for_code(controller):
    dialog = MultiLineDialog(controller, "Code for the patch?")
    dialog.exec_()


def ask_for_size(controller):
    dialog = SingleLineDialog(controller, "Size of the patch?")
    dialog.exec_()
    arg = controller.new_patch_args[-1]
    controller.new_patch_args[-1] = int(arg)


def ask_for_bytes(controller):
    dialog = MultiLineDialog(controller, "Bytes to use for the patch?")
    dialog.exec_()
    arg = controller.new_patch_args[-1]
    controller.new_patch_args[-1] = arg.encode()


def ask_for_address(controller):
    dialog = SingleLineDialog(
        controller, "Address to use for the patch? (start it with 0x)"
    )
    dialog.exec_()
    arg = controller.new_patch_args[-1]
    controller.new_patch_args[-1] = int(arg, 16)


def ask_for_address_or_name(controller):
    dialog = SingleLineDialog(
        controller,
        "Address or name to use for the patch? (if address, start it with 0x)",
    )
    dialog.exec_()
    arg = controller.new_patch_args[-1]

    if arg[:2] == "0x":
        controller.new_patch_args[-1] = int(arg, 16)


def display_message(controller, message):
    dialog = MessageDialog(controller, message)
    dialog.exec_()

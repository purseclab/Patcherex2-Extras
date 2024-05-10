from libbs.ui.qt_objects import (
    QDialog,
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
    from PySide6.QtWidgets import (
        QButtonGroup,
        QRadioButton,
        QTextEdit,
    )
else:
    from PyQt5.QtWidgets import (
        QButtonGroup,
        QRadioButton,
        QTextEdit,
    )

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

        added_patches = QLabel()
        added_patches.setText("Added Patches:")
        added_patches.setAlignment(Qt.AlignCenter)

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

        self.main_layout.addWidget(added_patches)
        self.main_layout.addWidget(scroll_area)
        self.main_layout.addLayout(bottom_layout)

        self.setLayout(self.main_layout)

    def patch_binary(self):
        binary_path = self.controller.deci.binary_path
        p = Patcherex(binary_path)
        p.patches = [i.patch for i in self.controller.patches]
        p.apply_patches()
        p.binfmt_tool.save_binary(binary_path + "-patched")
        display_message(
            self.controller,
            "Binary patched! A new file with '-patched' appended has been made. Load it to see the changes.",
        )

    def add_patch(self):
        dialog = PatchSelector(self.controller)
        dialog.exec_()

        self.controller.new_patch_args = []
        if self.controller.new_patch_type == "ModifyRawBytesPatch":
            ask_for_address(self.controller)
            ask_for_bytes(self.controller)
            patch = ModifyRawBytesPatch(*self.controller.new_patch_args)

        elif self.controller.new_patch_type == "ModifyDataPatch":
            ask_for_address(self.controller)
            ask_for_bytes(self.controller)
            patch = ModifyDataPatch(*self.controller.new_patch_args)

        elif self.controller.new_patch_type == "InsertDataPatch":
            ask_for_address_or_name(self.controller)
            ask_for_bytes(self.controller)
            patch = InsertDataPatch(*self.controller.new_patch_args)

        elif self.controller.new_patch_type == "RemoveDataPatch":
            ask_for_address(self.controller)
            ask_for_size(self.controller)
            patch = RemoveDataPatch(*self.controller.new_patch_args)

        elif self.controller.new_patch_type == "ModifyFunctionPatch":
            ask_for_address_or_name(self.controller)
            ask_for_code(self.controller)
            patch = ModifyFunctionPatch(*self.controller.new_patch_args)

        elif self.controller.new_patch_type == "InsertFunctionPatch":
            ask_for_address_or_name(self.controller)
            ask_for_code(self.controller)
            patch = InsertFunctionPatch(*self.controller.new_patch_args)

        elif self.controller.new_patch_type == "RemoveFunctionPatch":
            display_message(self.controller, "Not Implemented")
            return

        elif self.controller.new_patch_type == "ModifyInstructionPatch":
            ask_for_address(self.controller)
            ask_for_instructions(self.controller)
            patch = ModifyInstructionPatch(*self.controller.new_patch_args)

        elif self.controller.new_patch_type == "InsertInstructionPatch":
            ask_for_address_or_name(self.controller)
            ask_for_instructions(self.controller)
            patch = InsertInstructionPatch(*self.controller.new_patch_args)

        elif self.controller.new_patch_type == "RemoveInstructionPatch":
            ask_for_address(self.controller)
            ask_for_size(self.controller)
            patch = RemoveInstructionPatch(*self.controller.new_patch_args)

        ui_patch = UIPatch(
            self.controller,
            self.controller.new_patch_type,
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

        self.setWindowTitle("Configure Patcherex2")
        self.setMinimumSize(300, 250)
        self.main_layout = QVBoxLayout()
        self.main_layout.setAlignment(Qt.AlignCenter)

        not_implemented = QLabel(self)
        not_implemented.setText("This Section is Not Implemented")
        ok_button = QPushButton(self)
        ok_button.setText("Ok")
        ok_button.clicked.connect(self.on_ok_clicked)

        self.main_layout.addWidget(not_implemented)
        self.main_layout.addWidget(ok_button)

        self.setLayout(self.main_layout)

    def on_ok_clicked(self):
        self.close()


class PatchSelector(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Patcherex2")
        self.layout = QVBoxLayout()

        instructions = QLabel("Which Patch Would You Like to Add?")
        self.layout.addWidget(instructions)

        self.button_group = QButtonGroup(self)  # Group for mutually exclusive selection

        choices = [
            "ModifyRawBytesPatch",
            "ModifyDataPatch",
            "InsertDataPatch",
            "RemoveDataPatch",
            "ModifyFunctionPatch",
            "InsertFunctionPatch",
            "RemoveFunctionPatch",
            "ModifyInstructionPatch",
            "InsertInstructionPatch",
            "RemoveInstructionPatch",
        ]

        self.radio_buttons = []
        for i, choice in enumerate(choices):
            radio_button = QRadioButton(choice)
            self.radio_buttons.append(radio_button)
            self.button_group.addButton(radio_button, id=i)
            self.layout.addWidget(radio_button)

        self.radio_buttons[0].setChecked(True)

        confirm_button = QPushButton("Confirm")
        confirm_button.clicked.connect(self.confirm_selection)
        self.layout.addWidget(confirm_button)

        self.setLayout(self.layout)

    def confirm_selection(self):
        choice = self.button_group.checkedButton().text()
        self.controller.new_patch_type = choice
        self.close()


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

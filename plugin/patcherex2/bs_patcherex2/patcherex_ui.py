from libbs.ui.qt_objects import (
    QDialog,
    QLabel,
    QObject,
    QPushButton,
    Qt.AlignCenter,
    QHBoxLayout,
    QVBoxLayout,
    QWidget,
)


class PatcherexUIWorker(QObject):
    def __init__(self):
        QObject.__init__(self)

    def run(self):
        dialog = PatcherexDialog()
        dialog.exec_()


class PatcherexDialog(QDialog):
    def __init__(self, controller, parent):
        super().__init__(self, parent=parent)
        self.controller = controller
        self.setWindowTitle("test")

class ControlPanel(QWidget):
    def __init__(self, controller, parent=None):
        super(ControlPanel, self).__init__(parent)
        self.controller = controller
        self.main_layout = QVBoxLayout()

        added_patches = QLabel()
        added_patches.setText("Added Patches:")
        added_patches.setAlignment(Qt.AlignCenter)

        self.patch_layout = QVBoxLayout()
        self.patch_layout.setAlignment(Qt.AlignCenter)

        for i in self.controller.patches:
            self.add_patch(i)
        
        add_patch = QPushButton()
        add_patch.setText("Add a New Patch")
        add_patch.clicked.connect(self.add_patch)

        self.main_layout.addWidget(added_patches)
        self.main_layout.addLayout(self.patch_layout)
        self.main_layout.addWidget(add_patch)

        self.setLayout(self.main_layout)

    def add_patch(self, name="Patch"):
        patch = UIPatch(name, parent=self)
        self.patch_layout.addWidget(patch)
        #self.controller.patches.append(patch)
        self.update()

class UIPatch(QWidget):
    def __init__(self, patch_name, parent=None):
        self.parent = parent
        self.main_layout = QHBoxLayout()
        name = QLabel()
        name.setText(patch_name)
        remove = QPushButton()
        remove.setText("Remove")
        #remove.clicked.connect(self.remove_from_parent)

        self.main_layout.addWidget(name)
        self.main_layout.addWidget(remove)
        self.setLayout(self.main_layout)
    
    def remove_from_parent(self):
        self.parent.removeWidget(self)
        self.parent.update()


class ConfigurePatcherexDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller

        self.setWindowTitle("Configure Patcherex")
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



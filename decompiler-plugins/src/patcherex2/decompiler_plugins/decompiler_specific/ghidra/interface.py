import sys

from libbs.api import DecompilerInterface
from libbs.decompilers import GHIDRA_DECOMPILER
from libbs.ui.qt_objects import QApplication, QMainWindow
from libbs.ui.version import set_ui_version

from ...controller import Patcherex2Controller
from ...ui import ConfigurePatcherex2Dialog, ControlPanel

set_ui_version("PySide6")


class ControlPanelWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Patcherex2")
        self.setMinimumSize(500, 450)

        self._interface = DecompilerInterface.discover(
            force_decompiler=GHIDRA_DECOMPILER
        )
        self.controller = Patcherex2Controller(self._interface)
        self.control_panel = ControlPanel(self.controller)
        self._init_widgets()

    def _init_widgets(self):
        self.control_panel.show()
        self.setCentralWidget(self.control_panel)

    def configure(self):
        config = ConfigurePatcherex2Dialog(self.controller)
        config.show()
        config.exec_()
        return True

    def closeEvent(self, event):  # noqa
        self.controller.shutdown()


def start_ghidra_remote_ui():
    app = QApplication()
    cp_window = ControlPanelWindow()

    cp_window.hide()
    connected = cp_window.configure()
    if connected:
        cp_window.show()
    else:
        sys.exit(1)

    app.exec_()
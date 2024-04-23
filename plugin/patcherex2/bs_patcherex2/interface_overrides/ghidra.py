import logging
import sys

from libbs.ui.version import set_ui_version
set_ui_version("PySide6")
from libbs.ui.qt_objects import QMainWindow, QApplication
from libbs.api import DecompilerInterface
from libbs.decompilers import GHIDRA_DECOMPILER

from ..patcherex_ui import ControlPanel
from ..controller import PatcherexController
from ..patcherex_ui import PatcherexDialog
from ..patcherex_ui import ConfigurePatcherexDialog

l = logging.getLogger(__name__)


class ControlPanelWindow(QMainWindow):

    def __init__(self):
        super(ControlPanelWindow, self).__init__()
        self.setWindowTitle("Patcherex")
        self.setMinimumSize(500, 450)

        self._interface = DecompilerInterface.discover(force_decompiler=GHIDRA_DECOMPILER)
        self.controller = PatcherexController(self._interface)
        self.control_panel = ControlPanel(self.controller)
        self._init_widgets()

    def _init_widgets(self):
        self.control_panel.show()
        self.setCentralWidget(self.control_panel)

    def configure(self):
        config = ConfigurePatcherexDialog(self.controller)
        config.show()
        config.exec_()
        return True

    def closeEvent(self, event):
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
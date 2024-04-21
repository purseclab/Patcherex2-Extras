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

l = logging.getLogger(__name__)


class ControlPanelWindow(QMainWindow):
    """
    The class for the window that shows changes/info to BinSync data. This includes things like
    changes to functions or structs.
    """

    def __init__(self):
        super(ControlPanelWindow, self).__init__()
        self.setWindowTitle("Patcherex")
        self.width_hint = 300

        self._interface = DecompilerInterface.discover(force_decompiler=GHIDRA_DECOMPILER)
        self.controller = PatcherexController(self._interface)
        self.control_panel = ControlPanel(self.controller)
        self._init_widgets()

    def _init_widgets(self):
        self.control_panel.show()
        self.setCentralWidget(self.control_panel)

    #
    # handlers
    #

    # def configure(self):
    #     config = ConfigureBSDialog(self.controller)
    #     config.show()
    #     config.exec_()
    #     return self.controller.check_client()

    def closeEvent(self, event):
        self.controller.shutdown()


def start_ghidra_remote_ui():
    app = QApplication()
    cp_window = ControlPanelWindow()

    # control panel should stay hidden until a good config happens

    cp_window.show()
    # dialog = PatcherexDialog(cp_window.controller)
    # dialog.show()
    # dialog.exec_()

    app.exec_()
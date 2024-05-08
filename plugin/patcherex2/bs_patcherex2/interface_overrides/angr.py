import logging
import typing

from libbs.ui.version import set_ui_version
set_ui_version("PySide6")

from libbs.ui.qt_objects import QVBoxLayout
from libbs.decompilers.angr.compat import GenericBSAngrManagementPlugin

from angrmanagement.ui.views.view import BaseView

from ..patcherex_ui import ControlPanel
from ..controller import PatcherexController
from ..patcherex_ui import ConfigurePatcherexDialog

if typing.TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


_l = logging.getLogger(__name__)

class ControlPanelView(BaseView):
    """
    The class for the window that shows changes/info to Patcherex data.
    """

    def __init__(self, instance, default_docking_position, controller, *args, **kwargs):
        super().__init__('patching', instance.workspace, default_docking_position, *args, **kwargs)
        self.base_caption = "Patcherex2: Control Panel"
        self.controller: PatcherexController = controller
        self.control_panel = ControlPanel(self.controller)
        self._init_widgets()
        self.width_hint = 300

    def reload(self):
        pass

    def _init_widgets(self):
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.control_panel)
        self.setLayout(main_layout)


class PatcherexPlugin(GenericBSAngrManagementPlugin):
    """
    Controller plugin for BinSync
    """
    def __init__(self, workspace: "Workspace"):
        """
        The entry point for the Patcherex plugin. This class is responsible for both initializing the GUI and
        deiniting it as well.

        @param workspace:   an AM _workspace (usually found in _instance)
        """
        super().__init__(workspace)

        # construct the controller and control panel
        self.controller = PatcherexController(self.interface)
        self.control_panel_view = ControlPanelView(workspace.main_instance, 'right', self.controller)
        self.controller.control_panel = self.control_panel_view

        self.sync_menu = None
        self.selected_funcs = []

    def teardown(self):
        del self.controller.deci
        self.workspace.remove_view(self.control_panel_view)

    #
    # BinSync Menu
    #

    MENU_BUTTONS = ('Configure Patcherex2 ...', 'Toggle Patcherex2 Panel')
    MENU_CONFIG_ID = 0
    MENU_TOGGLE_PANEL_ID = 1

    def handle_click_menu(self, idx):
        # sanity check on menu selection
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        mapping = {
            self.MENU_CONFIG_ID: self.open_sync_config_dialog,
            self.MENU_TOGGLE_PANEL_ID: self.toggle_sync_panel
        }

        # call option mapped to each menu pos
        mapping.get(idx)()

    def open_sync_config_dialog(self):

        sync_config = ConfigurePatcherexDialog(self.controller)
        sync_config.exec_()

        if self.control_panel_view not in self.workspace.view_manager.views:
            self.workspace.add_view(self.control_panel_view)

    def toggle_sync_panel(self):
        if self.control_panel_view.isVisible():
            self.control_panel_view.close()
            return
        
        self.workspace.add_view(self.control_panel_view)

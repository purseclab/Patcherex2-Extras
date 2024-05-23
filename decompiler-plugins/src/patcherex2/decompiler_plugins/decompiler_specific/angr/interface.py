import typing

from angrmanagement.ui.views.view import BaseView
from libbs.decompilers.angr.compat import GenericBSAngrManagementPlugin
from libbs.ui.qt_objects import QVBoxLayout
from libbs.ui.version import set_ui_version

from ...controller import Patcherex2Controller
from ...ui import ControlPanel

if typing.TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


set_ui_version("PySide6")


class ControlPanelView(BaseView):
    """
    The class for the window that shows changes/info to Patcherex2 data.
    """

    def __init__(self, instance, default_docking_position, controller, *args, **kwargs):
        super().__init__(
            "patching", instance.workspace, default_docking_position, *args, **kwargs
        )
        self.base_caption = "Patcherex2: Control Panel"
        self.controller: Patcherex2Controller = controller
        self.control_panel = ControlPanel(self.controller)
        self._init_widgets()
        self.width_hint = 300

    def reload(self):
        pass

    def _init_widgets(self):
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.control_panel)
        self.setLayout(main_layout)


class Patcherex2Plugin(GenericBSAngrManagementPlugin):
    """
    Controller plugin for BinSync
    """

    def __init__(self, workspace: "Workspace"):
        """
        The entry point for the Patcherex2 plugin. This class is responsible for both initializing the GUI and
        deiniting it as well.

        @param workspace:   an AM _workspace (usually found in _instance)
        """
        super().__init__(workspace)

        # construct the controller and control panel
        self.controller = Patcherex2Controller(self.interface)
        self.control_panel_view = ControlPanelView(
            workspace.main_instance, "right", self.controller
        )
        self.controller.control_panel = self.control_panel_view
        self.controller.workspace = workspace

    def teardown(self):
        del self.controller.deci
        self.workspace.remove_view(self.control_panel_view)

    #
    # BinSync Menu
    #

    MENU_BUTTONS = ("Start Patcherex2...", "Toggle Patcherex2 Panel")
    MENU_CONFIG_ID = 0
    MENU_TOGGLE_ID = 1

    def handle_click_menu(self, idx):
        # sanity check on menu selection
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        mapping = {
            self.MENU_CONFIG_ID: self.start_ui,
            self.MENU_TOGGLE_ID: self.toggle_panel
        }

        # call option mapped to each menu pos
        mapping.get(idx)()

    def start_ui(self):
        if self.control_panel_view not in self.workspace.view_manager.views:
            self.workspace.add_view(self.control_panel_view)

    def toggle_panel(self):
        if self.control_panel_view.isVisible():
            self.control_panel_view.close()
        else:
            self.workspace.add_view(self.control_panel_view)

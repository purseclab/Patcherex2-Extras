import typing

from angrmanagement.ui.views.view import BaseView
from libbs.decompilers.angr.compat import GenericBSAngrManagementPlugin
from libbs.ui.qt_objects import QVBoxLayout
from libbs.ui.version import set_ui_version
from PySide6QtAds import CDockManager, CDockWidget, SideBarRight
from ...controller import Patcherex2Controller
from ...ui import ControlPanel

if typing.TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace

from typing import *

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
        self.control_panel: ControlPanel = ControlPanel(self.controller)
        self._init_widgets()
        self.width_hint = 500

    def reload(self):
        pass

    def close(self):
        self.hide()

    def closeEvent(self, event):
        self.hide()
        event.ignore()

    def _init_widgets(self):
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.control_panel)
        self.setLayout(main_layout)


class Patcherex2Plugin(GenericBSAngrManagementPlugin):
    """
    Controller plugin for Patcherex2
    """

    def __init__(self, workspace: "Workspace"):
        """
        The entry point for the Patcherex2 plugin. This class is responsible for both initializing the GUI and
        deiniting it as well.

        @param workspace:   an AM _workspace (usually found in _instance)
        """
        super().__init__(workspace)

        # construct the controller and control panel
        self.controller: Patcherex2Controller = Patcherex2Controller(self.interface)
        self.control_panel_view: ControlPanelView = ControlPanelView(
            workspace.main_instance, "right", self.controller
        )


    def teardown(self):
        del self.controller.deci
        self.workspace.remove_view(self.control_panel_view)


    MENU_BUTTONS = ("Toggle Patcherex2 Panel",)
    MENU_TOGGLE_ID = 0

    def handle_click_menu(self, idx):
        # sanity check on menu selection
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        mapping = {
            self.MENU_TOGGLE_ID: self.toggle_panel
        }

        # call option mapped to each menu pos
        mapping.get(idx)()


    def toggle_panel(self):
        if self.control_panel_view in self.workspace.view_manager.views:
            self.workspace.remove_view(self.control_panel_view)
        else:
            self.workspace.add_view(self.control_panel_view)
            dock = self.workspace.view_manager.view_to_dock[self.control_panel_view]
            dock.closed.disconnect()
            dock.setFeature(CDockWidget.DockWidgetDeleteOnClose, False)

    def build_context_menu_insn(
        self, insn
    ) -> Iterable[None | tuple[str, Callable[..., Any]]]:
        return [("Patcherex2", self.control_panel_view.control_panel.add_patch)]

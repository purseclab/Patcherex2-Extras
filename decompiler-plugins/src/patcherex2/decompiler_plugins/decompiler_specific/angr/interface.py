import itertools
import typing

from angr import Block
from angr.block import CapstoneInsn
from angr.knowledge_plugins.functions.function import Function
from angrmanagement.data.instance import Instance
from angrmanagement.data.jobs.cfg_generation import CFGGenerationJob
from angrmanagement.data.jobs.loading import LoadBinaryJob
from angrmanagement.ui.views.disassembly_view import DisassemblyView
from angrmanagement.ui.views.view import BaseView
from angrmanagement.utils import locate_function
from libbs.decompilers.angr.compat import GenericBSAngrManagementPlugin
from libbs.ui.qt_objects import QVBoxLayout
from libbs.ui.version import set_ui_version
from PySide6.QtGui import QColor
from PySide6QtAds import CDockManager, CDockWidget, SideBarRight

from ...controller import Patcherex2Controller, UIPatch
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
        self.width_hint = 600

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

        self.interface.angr_plugin = self

        self.patched_instance: Instance = None
        self.patched_view: DisassemblyView = None
        self.original_view: DisassemblyView = None
        self.patch_addrs: set = None
        self.remove_addrs: set = None

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

        mapping = {self.MENU_TOGGLE_ID: self.toggle_panel}

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

    def open_panel(self):
        if self.control_panel_view not in self.workspace.view_manager.views:
            self.workspace.add_view(self.control_panel_view)
            dock = self.workspace.view_manager.view_to_dock[self.control_panel_view]
            dock.closed.disconnect()
            dock.setFeature(CDockWidget.DockWidgetDeleteOnClose, False)

    def build_context_menu_insn(
        self, insn
    ) -> Iterable[None | tuple[str, Callable[..., Any]]]:
        return [("Patcherex2", self.control_panel_view.control_panel.add_patch)]

    def color_insn(self, addr: int, selected, disasm_view) -> QColor | None:
        if disasm_view is self.patched_view:
            if addr in self.patch_addrs:
                return QColor(0, 100, 160)
            elif addr in self.remove_addrs:
                return QColor(150, 100, 0)
            else:
                return None
        elif disasm_view is self.original_view:
            if addr in self.patch_addrs or addr in self.remove_addrs:
                return QColor(200, 150, 0)
            else:
                return None

    def function_instrs(self, func: Function) -> dict[int, CapstoneInsn]:
        sorted_blocks = sorted(func.blocks, key=lambda b: b.addr)
        instruction_lists = [block.disassembly.insns for block in sorted_blocks]
        instructions = list(itertools.chain.from_iterable(instruction_lists))

        return {i.address: i for i in instructions}

    def get_block(func: Function, addr: int) -> Block:
        for b in func.blocks:
            if addr - b.addr < b.size:
                return b
        return None

    def fill_patch_addrs(self):
        patches: list[UIPatch] = self.controller.patched_patches

        proj = self.workspace.main_instance.project
        offset = (
            proj.loader.main_object.mapped_base if proj.loader.main_object.pic else 0
        )

        for patch in patches:
            match patch.patch_type:
                case "ModifyDataPatch":
                    start = patch.args["addr"] + offset
                    for a in range(start, start + len(patch.args["new_bytes"])):
                        self.patch_addrs.add(a)
                case "InsertDataPatch":
                    loc = patch.args["addr_or_name"]
                    if isinstance(loc, str):
                        try:
                            loc = self.patched_instance.kb.functions[loc].addr
                        except:
                            continue
                    else:
                        loc = loc + offset
                    for a in range(loc, loc + len(patch.args["data"])):
                        self.patch_addrs.add(a)
                case "RemoveDataPatch":
                    pass
                case "ModifyInstructionPatch":
                    addr = patch.args["addr"] + offset
                    og_fn: Function = locate_function(self.original_view.instance, addr)
                    ptc_fn: Function = locate_function(self.patched_instance, addr)
                    if not og_fn or not ptc_fn:
                        continue
                    addr = og_fn.addr_to_instruction_addr(addr)
                    if not addr:
                        continue
                    og_instrs = self.function_instrs(og_fn)
                    ptc_instrs = self.function_instrs(ptc_fn)
                    og_i = og_instrs[addr]
                    ptc_i = ptc_instrs[addr]
                    while True:
                        if not og_i or not ptc_i:
                            break
                        if (
                            og_i.address == ptc_i.address
                            and og_i.mnemonic == ptc_i.mnemonic
                            and og_i.op_str == ptc_i.op_str
                        ):
                            break
                        self.patch_addrs.add(og_i.address)
                        self.patch_addrs.add(ptc_i.address)
                        if og_i.address + og_i.size <= ptc_i.address + ptc_i.size:
                            og_next = og_instrs[og_i.address + og_i.size]
                        else:
                            og_next = og_i
                        if ptc_i.address + ptc_i.size <= og_i.address + og_i.size:
                            ptc_next = ptc_instrs[ptc_i.address + ptc_i.size]
                        else:
                            ptc_next = ptc_i
                        og_i = og_next
                        ptc_i = ptc_next
                case "InsertInstructionPatch":
                    loc = patch.args["addr_or_name"]
                    if isinstance(loc, int):
                        loc = loc + offset
                        self.patch_addrs.add(loc)
                        func = locate_function(self.patched_instance, loc)
                        try:
                            jump = self.function_instrs(func)[loc]
                        except:
                            continue
                        loc = int(jump.op_str, 16)
                        try:
                            func = self.patched_instance.kb.functions[loc]
                        except:
                            continue
                        instrs = self.function_instrs(func)
                        addrs = sorted(instrs.keys())
                        for i in addrs:
                            instr = instrs[i]
                            self.patch_addrs.add(instr.address)
                        try:
                            dest = int(instr.op_str, 16)
                            for i in range(jump.address + jump.size, dest):
                                self.remove_addrs.add(i)
                        except:
                            pass
                    else:
                        try:
                            func = self.patched_instance.kb.functions[loc]
                        except:
                            continue
                        for i in range(func.addr, func.addr + func.size):
                            self.patch_addrs.add(i)
                case "RemoveInstructionPatch":
                    pass
                case "ModifyFunctionPatch":
                    loc = patch.args["addr_or_name"]
                    if isinstance(loc, int):
                        loc += offset
                    try:
                        func = self.patched_instance.kb.functions[loc]
                        og_func = self.original_view.instance.kb.functions[loc]
                    except:
                        continue
                    if og_func.size > func.size:
                        for i in range(func.addr, func.addr + func.size):
                            self.patch_addrs.add(i)
                        for i in range(
                            func.addr + func.size, og_func.addr + og_func.size
                        ):
                            self.remove_addrs.add(i)
                    else:
                        #TODO trampoline functions
                        pass 
                case "InsertFunctionPatch":
                    loc = patch.args["addr_or_name"]
                    if isinstance(loc, int):
                        loc += offset
                    try:
                        func = self.patched_instance.kb.functions[loc]
                    except:
                        continue
                    for i in range(func.addr, func.addr + func.size):
                        self.patch_addrs.add(i)

    def load_patched_binary(self, filename: str):
        self.destroy_patched_view()
        self.patch_addrs = set()
        self.remove_addrs = set()
        self.patched_instance = Instance()
        self._create_instance_from_binary(filename)

    def create_patched_view(self):
        new_disass = DisassemblyView(self.workspace, "right", self.patched_instance)
        new_disass.category = "patcherex2"
        new_disass.base_caption = "Patcherex2: Patched binary"
        self.patched_view = new_disass
        self.workspace.add_view(self.patched_view)

    def destroy_patched_view(self):
        if self.patched_view:
            self.workspace.remove_view(self.patched_view)
            del self.patched_view
        if self.patched_instance:
            del self.patched_instance

    def _create_instance_from_binary(self, file_path: str) -> None:
        self.patched_instance.workspace = self.workspace

        job = LoadBinaryJob(file_path, on_finish=self._create_instance_from_binary_done)
        self.loaded_binary = file_path
        self.patched_instance.job_manager.add_job(job)

    def _create_instance_from_binary_done(self, *args, **kwargs) -> None:  # pylint:disable=unused-argument
        job = CFGGenerationJob(on_finish=self._generate_binary_cfg_done)
        self.patched_instance.job_manager.add_job(job)

    def _generate_binary_cfg_done(self, inst, cfg_info, *args, **kwargs) -> None:  # pylint:disable=unused-argument
        cfg_model, _ = cfg_info
        self.patched_instance.cfg = cfg_model
        self.patched_binary_loaded()

    def patched_binary_loaded(self):
        self.create_patched_view()
        self.workspace.view_manager.raise_view(self.patched_view)

        self.original_view = self.patched_instance.workspace._get_or_create_view(
            "disassembly", DisassemblyView
        )

        self.patched_view.jump_to(self.original_view.function.addr)

        self.fill_patch_addrs()

import logging

from angrmanagement.ui.views import DisassemblyView
from libbs.api import DecompilerInterface
from libbs.decompilers.angr.interface import AngrInterface
from libbs.decompilers.ghidra.interface import GhidraDecompilerInterface


log = logging.getLogger("patcherex2")


def get_ctx_address(deci: DecompilerInterface):
    try:
        if isinstance(deci, AngrInterface):
            # NOTE: need to find actual api way to do this
            curr_view: DisassemblyView = deci.workspace.view_manager.current_tab
            proj = deci.workspace.main_instance.project
            offset = (
                proj.loader.main_object.mapped_base if proj.loader.main_object.pic else 0
            )
            return curr_view._insn_addr_on_context_menu - offset
        elif isinstance(deci, GhidraDecompilerInterface):
            return deci.ghidra.currentAddress.getOffset()
    except Exception:
        return None


def load_patched_binary(deci: DecompilerInterface, binary_path: str):
    if isinstance(deci, AngrInterface):
        deci.angr_plugin.load_patched_binary(f"{binary_path}.patched")
    elif isinstance(deci, GhidraDecompilerInterface):
        pass

        # f = deci.ghidra.bridge.remote_import("java.io.File")(f"{binary_path}.patched")
        # program = deci.ghidra.importFile(f)
        # f.close()
        # deci.ghidra.state.setCurrentProgram(program)
from angrmanagement.ui.views import DisassemblyView
from libbs.api import DecompilerInterface
from libbs.decompilers.angr.interface import AngrInterface
from libbs.decompilers.ghidra.interface import GhidraDecompilerInterface


def get_ctx_address(deci: DecompilerInterface):
    try:
        if isinstance(deci, AngrInterface):
            # NOTE: need to find actual api way to do this
            curr_view: DisassemblyView = deci.workspace.view_manager.current_tab
            return curr_view._insn_addr_on_context_menu
        elif isinstance(deci, GhidraDecompilerInterface):
            return deci.ghidra.currentAddress.getOffset()
    except Exception:
        return None


def load_patched_binary(deci: GhidraDecompilerInterface, binary_path: str):
    if isinstance(deci, AngrInterface):
        from angrmanagement.plugins.precise_diffing.precisediff_plugin import (
            PreciseDiffPlugin,
        )

        diff_plugin = PreciseDiffPlugin(deci.workspace)
        diff_plugin.load_revised_binary_from_file(f"{binary_path}.patched")
    elif isinstance(deci, GhidraDecompilerInterface):
        
        f = deci.ghidra.bridge.remote_import("java.io.File")(f"{binary_path}.patched")
        program = deci.ghidra.importFile(f)
        f.close()
        deci.ghidra.state.setCurrentProgram(program)

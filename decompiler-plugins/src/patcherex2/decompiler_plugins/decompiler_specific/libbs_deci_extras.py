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
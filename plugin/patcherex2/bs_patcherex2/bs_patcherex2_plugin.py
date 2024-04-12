# Plugin that allows you to use Patcherex2 in the most common decompilers
# @author PurSec Lab
# @category Patcherex2
# @menupath Tools.Patcherex2.Start the BS backend for Patcherex2

# pyright: reportMissingImports=false

plugin_command = "bs_patcherex2 -s ghidra"


def create_plugin(*args, **kwargs):
    from bs_patcherex2 import create_plugin as _create_plugin

    return _create_plugin(*args, **kwargs)


# =============================================================================
# LibBS generic plugin loader (don't touch)
# =============================================================================

import sys  # noqa E402

# Python 2 has special requirements for Ghidra, which forces us to use a different entry point
# and scope for defining plugin entry points
if sys.version[0] == "2":
    # Do Ghidra Py2 entry point
    import subprocess

    from libbs_vendored.ghidra_bridge_server import GhidraBridgeServer

    GhidraBridgeServer.run_server(background=True)
    process = subprocess.Popen(plugin_command.split(" "))
    if process.poll() is not None:
        raise RuntimeError(
            "Failed to run the Python3 backed. It's likely Python3 is not in your Path inside Ghidra."
        )
else:
    # Try plugin discovery for other decompilers
    try:
        import idaapi  # noqa F401

        has_ida = True
    except ImportError:
        has_ida = False
    try:
        import angrmanagement  # noqa F401

        has_angr = True
    except ImportError:
        has_angr = False

    if not has_ida and not has_angr:
        create_plugin()
    elif has_angr:
        from angrmanagement.plugins import BasePlugin

        class AngrBSPluginThunk(BasePlugin):
            def __init__(self, workspace):
                super().__init__(workspace)
                globals()["workspace"] = workspace
                self.plugin = create_plugin()

            def teardown(self):
                pass


def PLUGIN_ENTRY(*args, **kwargs):  # noqa N802
    """
    This is the entry point for IDA to load the plugin.
    """
    return create_plugin(*args, **kwargs)

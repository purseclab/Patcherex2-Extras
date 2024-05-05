from pathlib import Path

from libbs.plugin_installer import LibBSPluginInstaller

from .controller import PatcherexController
from .patcherex_utils import add_patch

__version__ = "0.0.1"


def create_plugin(*args, **kwargs):
    """
    This is the entry point that all decompilers will call in various ways. To remain agnostic,
    always pass the args and kwargs to the gui_init_args and gui_init_kwargs of DecompilerInterface, inited
    through the discover api.
    """

    from libbs.api import DecompilerInterface
    from libbs.decompilers import ANGR_DECOMPILER

    current_decompiler = DecompilerInterface.find_current_decompiler()

    is_angr = (current_decompiler == ANGR_DECOMPILER)
    
    if not is_angr:
        deci = DecompilerInterface.discover(
            plugin_name="Patcherex2",
            init_plugin=True,
            gui_init_args=args,
            gui_init_kwargs=kwargs,
        )
        return deci.gui_plugin


class BSPatcherex2Installer(LibBSPluginInstaller):
    """
    This acts as a simple installer for the plugin
    """

    def __init__(self):
        super().__init__()
        self.pkg_path = self.find_pkg_files("bs_patcherex2")

    def _copy_plugin_to_path(self, path):
        src = self.pkg_path / "bs_patcherex2_plugin.py"
        dst = Path(path) / "bs_patcherex2_plugin.py"
        self.link_or_copy(src, dst, symlink=True)

    def display_prologue(self):
        print("Now installing BSPatcherex2 plugin...")

    def install_ida(self, path=None, interactive=True):
        path = super().install_ida(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path

    def install_ghidra(self, path=None, interactive=True):
        path = super().install_ghidra(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path

    def install_binja(self, path=None, interactive=True):
        path = super().install_binja(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path

    def install_angr(self, path=None, interactive=True):
        path = super().install_angr(path=path, interactive=interactive)
        if not path:
            return

        path = path / "bs_patcherex2"
        path.mkdir(parents=True, exist_ok=True)
        src = self.pkg_path / "plugin.toml"
        dst = Path(path) / "plugin.toml"
        self.link_or_copy(src, dst, symlink=True)
        self._copy_plugin_to_path(path)
        return path

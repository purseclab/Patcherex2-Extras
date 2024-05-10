import shutil
from pathlib import Path

from libbs.plugin_installer import LibBSPluginInstaller


class Patcherex2PluginInstaller(LibBSPluginInstaller):
    """
    This acts as a simple installer for the plugin
    """

    def __init__(self):
        super().__init__(targets=["ghidra", "angr"])
        self.pkg_path = self.find_pkg_files("patcherex2.decompiler_plugins")
        if self.pkg_path is None:
            raise RuntimeError(
                "Could not find binsync package files. Please reinstall or report on GitHub."
            )

    def _copy_plugin_to_path(self, path):
        src = self.pkg_path / "patcherex2_plugin.py"
        dst = Path(path) / "patcherex2_plugin.py"
        self.link_or_copy(src, dst, symlink=True)

    def display_prologue(self):
        print("Installing Patcherex2 plugin...")

    def install_ghidra(self, path=None, interactive=True):
        path = super().install_ghidra(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path

    def install_angr(self, path=None, interactive=True):
        path = super().install_angr(path=path, interactive=interactive)
        if not path:
            return

        angr_specific_path = self.pkg_path / "decompiler_specific" / "angr"
        angr_patcherex2_plugin_dir = path / "patcherex2"
        if angr_patcherex2_plugin_dir.exists():
            shutil.rmtree(angr_patcherex2_plugin_dir)
        angr_patcherex2_plugin_dir.mkdir(parents=True)

        self.link_or_copy(
            angr_specific_path / "plugin.toml",
            Path(angr_patcherex2_plugin_dir) / "plugin.toml",
            symlink=True,
        )
        self._copy_plugin_to_path(angr_patcherex2_plugin_dir)
        return path

import argparse

from . import create_plugin
from .installer import Patcherex2PluginInstaller


def main():
    parser = argparse.ArgumentParser(
        description="Plugin that allows you to use Patcherex2 in the most common decompilers"
    )
    parser.add_argument(
        "-i",
        "--install",
        action="store_true",
        help="Install plugin into your decompilers",
    )
    parser.add_argument(
        "-s",
        "--server",
        help="Run a headless server for the watcher plugin",
        choices=["ghidra"],
    )
    args = parser.parse_args()

    if args.install:
        Patcherex2PluginInstaller().install()
    elif args.server:
        if args.server != "ghidra":
            raise NotImplementedError("Only Ghidra is supported for now")
        from .decompiler_specific.ghidra.interface import start_ghidra_remote_ui

        start_ghidra_remote_ui()
        create_plugin(force_decompiler="ghidra")


if __name__ == "__main__":
    main()

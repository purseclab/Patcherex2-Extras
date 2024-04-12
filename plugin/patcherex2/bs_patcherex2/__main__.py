import argparse

import bs_patcherex2

from . import BSPatcherex2Installer, create_plugin


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
    parser.add_argument(
        "-v", "--version", action="version", version=bs_patcherex2.__version__
    )
    args = parser.parse_args()

    if args.install:
        BSPatcherex2Installer().install()
    elif args.server:
        if args.server != "ghidra":
            raise NotImplementedError("Only Ghidra is supported for now")

        create_plugin(force_decompiler="ghidra")


if __name__ == "__main__":
    main()

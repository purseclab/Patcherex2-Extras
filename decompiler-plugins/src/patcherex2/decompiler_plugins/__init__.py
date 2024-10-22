from importlib import metadata

__version__ = metadata.version("patcherex2-decompiler-plugins")


def create_plugin(*args, **kwargs):
    """
    This is the entry point that all decompilers will call in various ways. To remain agnostic,
    always pass the args and kwargs to the gui_init_args and gui_init_kwargs of DecompilerInterface, inited
    through the discover api.
    """

    from libbs.api import DecompilerInterface
    from libbs.decompilers import ANGR_DECOMPILER

    current_decompiler = DecompilerInterface.find_current_decompiler()
    if current_decompiler != ANGR_DECOMPILER:
        deci = DecompilerInterface.discover(
            plugin_name="Patcherex2",
            init_plugin=True,
            gui_init_args=args,
            gui_init_kwargs=kwargs,
        )
        return deci.gui_plugin

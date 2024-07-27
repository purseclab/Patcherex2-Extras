from dataclasses import dataclass

from libbs.api import DecompilerInterface


class Patcherex2Controller:
    def __init__(self, deci):
        self.deci: DecompilerInterface = deci
        self.target = "auto"
        self.patches: list[UIPatch] = []
        self.patched_patches: list[UIPatch]
        self.find_unused_space = False
        self.manually_added_unused_space = []

    def shutdown(self):
        self.deci.shutdown()


@dataclass
class UIPatch:
    patch_type: str
    args: dict

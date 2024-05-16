from libbs.api import DecompilerInterface

class Patcherex2Controller:
    def __init__(self, deci):
        self.deci: DecompilerInterface = deci
        self.target = "auto"
        self.patches = []
        self.find_unused_space = False
        self.manually_added_unused_space = []

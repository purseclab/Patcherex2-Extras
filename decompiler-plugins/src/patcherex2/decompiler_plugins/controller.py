class Patcherex2Controller:
    def __init__(self, deci):
        self.deci = deci
        self.target = "auto"
        self.patches = []
        self.find_unused_space = False
        self.manually_added_unused_space = []
        self.new_patch_args = []

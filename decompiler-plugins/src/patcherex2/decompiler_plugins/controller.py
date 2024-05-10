class Patcherex2Controller:
    def __init__(self, deci):
        self.deci = deci
        self.patches = []
        self.new_patch_type = ""
        self.new_patch_args = []

    def _init_ui_components(self):
        from libbs.ui.qt_objects import QThread

        from .ui import Patcherex2UIWorker

        self._ui_thread = QThread()
        self._ui_worker = Patcherex2UIWorker()
        self._ui_worker.moveToThread(self._ui_thread)
        self._ui_thread.started.connect(self._ui_worker.run)
        self._ui_thread.finished.connect(self._ui_thread.deleteLater)
        self._ui_thread.start()

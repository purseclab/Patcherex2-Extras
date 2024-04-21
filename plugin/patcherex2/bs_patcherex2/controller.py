class PatcherexController:
    def __init__(self, deci):
        self.deci = deci

    def _init_ui_components(self):
        from libbs.ui.qt_objects import (
            QThread,
        )

        from .patcherex_ui import PatcherexUIWorker

        self._ui_thread = QThread()
        self._ui_worker = PatcherexUIWorker()
        self._ui_worker.moveToThread(self._ui_thread)
        self._ui_thread.started.connect(self._ui_worker.run)
        self._ui_thread.finished.connect(self._ui_thread.deleteLater)
        self._ui_thread.start()
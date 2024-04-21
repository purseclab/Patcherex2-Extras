from libbs.ui.qt_objects import (
    QDialog,
    QObject,
    QWidget,
)


class PatcherexUIWorker(QObject):
    def __init__(self):
        QObject.__init__(self)

    def run(self):
        dialog = PatcherexDialog()
        dialog.exec_()


class PatcherexDialog(QDialog):
    def __init__(self, controller):
        super().__init__(self)
        self.controller = controller
        self.setWindowTitle("test")

class ControlPanel(QWidget):
    def __init__(self, controller, parent=None):
        super(ControlPanel, self).__init__(parent)
        self.controller = controller
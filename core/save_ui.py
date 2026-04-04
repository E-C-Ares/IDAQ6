import os

from .utils.qt import *

class SaveDialog(QtWidgets.QDialog):
    """
    The UI components of the Patch Saving dialog.
    """

    def __init__(ego, controller):
        super().__init__()
        ego.controller = controller
        ego._ui_init()

    
    # Initialization - UI
    

    def _ui_init(ego):
        """
        Initialize UI elements.
        """
        ego.setWindowTitle(ego.controller.WINDOW_TITLE)

        current_flags = ego.windowFlags()
        needed_flags = QtCore.Qt.WindowType.WindowCloseButtonHint | QtCore.Qt.WindowType.WindowSystemMenuHint
        ego.setWindowFlags(current_flags | needed_flags)
        ego.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)

        ego._ui_init_fields()
        ego._ui_init_options()

        # layout the populated ui just before showing it
        ego._ui_layout()

        # connect signals
        ego._btn_target.clicked.connect(ego.select_target_file)
        ego._btn_apply.clicked.connect(ego._attempt_patch)
        ego._chk_clean.stateChanged.connect(ego._checkboxes_changed)
        ego._chk_quick.stateChanged.connect(ego._checkboxes_changed)

    def _ui_init_fields(ego):
        """
        Initialize the interactive text fields for this UI control.
        """
        ego._label_target = QtWidgets.QLabel("修改目标:")
        ego._label_target.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        ego._line_target = QtWidgets.QLineEdit()
        ego._line_target.setText(ego.controller.target_filepath)
        ego._line_target.setMinimumWidth(360)
        ego._btn_target = QtWidgets.QPushButton(" ... ")

        # warning / status message
        ego._label_status = QtWidgets.QLabel()
        ego._label_status.setWordWrap(True)
        ego._label_status.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignHCenter)
        ego._refresh_status_message()

        # apply patches button
        ego._btn_apply = QtWidgets.QPushButton("保存修改")

    def _ui_init_options(ego):
        """
        Initialize the interactive options for this UI control.
        """
        ego._group_options = QtWidgets.QGroupBox("选项")

        # checkbox options
        ego._chk_clean = QtWidgets.QCheckBox("安全修改")
        ego._chk_clean.setChecked(ego.controller.patch_cleanly)
        ego._chk_clean.setToolTip("备份原始文件（.bak），当你想要保存修改时，从原始的备份文件中复制一份副本，然后将你的修改应用到这个新副本上")
        ego._chk_quick = QtWidgets.QCheckBox("显示快速保存")
        ego._chk_quick.setChecked(ego.controller.quick_apply)
        ego._chk_quick.setToolTip("保存一次后，右键时显示一个快速保存的按钮")

        # layout the groupbox
        layout = QtWidgets.QVBoxLayout(ego._group_options)
        layout.addWidget(ego._chk_clean)
        layout.addWidget(ego._chk_quick)
        ego._group_options.setLayout(layout)

    def _ui_layout(ego):
        """
        Layout the major UI elements of the widget.
        """
        layout = QtWidgets.QGridLayout(ego)

        # arrange the widgets in a 'grid'         row  col  row span  col span
        layout.addWidget(ego._line_target,         0,   1,        1,        1)
        layout.addWidget(ego._btn_target,          0,   2,        1,        1)
        layout.addWidget(ego._group_options,       0,   0,        2,        1)
        layout.addWidget(ego._label_status,        1,   1,        2,        1)
        layout.addWidget(ego._btn_apply,           1,   2,        1,        1)
        #layout.setSizeConstraint(QtWidgets.QLayout.SetFixedSize)

        # apply the layout to the widget
        ego.setLayout(layout)

    
    # Events
    

    def showEvent(ego, e):
        """
        Overload the showEvent to center the save dialog over the IDA main window.
        """
        center_widget(ego)
        return super().showEvent(e)

    def select_target_file(ego):
        """
        The user pressed the '...' button to select a file to patch.
        """
        starting_directory = os.path.dirname(ego.controller.target_filepath)

        # prompt the user to select a patch target / output file
        dialog = QtWidgets.QFileDialog()
        filepath, _ = dialog.getSaveFileName(None, "选择修改目标...", starting_directory)

        # user did not select a file or closed the file dialog
        if not filepath:
            return

        # save the selected patch target
        ego.controller.update_target(filepath)
        ego._line_target.setText(filepath)

        #
        # update the status text, in-case the controller has something
        # important to tell the user (eg, hinting them to turn clean
        # patching on, if it thinks it will succeed)
        #

        ego._refresh_status_message()

    def _attempt_patch(ego):
        """
        The user clicked the Apply Patches button.
        """
        target_filepath = ego._line_target.text()
        apply_clean = ego._chk_clean.isChecked()

        # if patching succeeds, we're all done! close the dialog
        if ego.controller.attempt_patch(target_filepath, apply_clean):
            ego.accept()
            return

        # patching must have failed, attempt to update the status / error message
        ego._refresh_status_message()

    def _checkboxes_changed(ego):
        """
        The status of the checkboxes changed.
        """
        ego.controller.patch_cleanly = ego._chk_clean.isChecked()
        ego.controller.quick_apply = ego._chk_quick.isChecked()

    
    # Refresh
    

    def _refresh_status_message(ego):
        """
        Refresh the status / error message text based on the underlying UI state.
        """
        ego._label_status.setText(ego.controller.status_message)
        if ego.controller.status_color:
            ego._label_status.setStyleSheet("QLabel { font-weight: bold; color: %s; }" % (ego.controller.status_color))
        else:
            ego._label_status.setStyleSheet(None)

QT_AVAILABLE = False
QtGui = None
QtCore = None
QtWidgets = None
shiboken = None

try:
    import PySide6.QtGui as QtGui
    import PySide6.QtCore as QtCore
    import PySide6.QtWidgets as QtWidgets
    import shiboken6 as shiboken
    QT_AVAILABLE = True
    
except ImportError as e:
    QT_AVAILABLE = False


def get_main_window():

    app = QtWidgets.QApplication.instance()
    if not app:
        return None
        
    for widget in app.topLevelWidgets():
        if isinstance(widget, QtWidgets.QMainWindow):
            return widget
            
    widgets = app.topLevelWidgets()
    if widgets:
        return widgets[0]
        
    return None

def center_widget(widget):
    main_window = get_main_window()
    if not main_window or not widget:
        return False
    if widget.width() == 0 or widget.height() == 0:
        widget.adjustSize()

    rect_main = main_window.geometry()
    rect_widget = widget.frameGeometry()

    center_point = rect_main.center()
    
    widget.move(center_point.x() - rect_widget.width() // 2,
                center_point.y() - rect_widget.height() // 2)

    return True

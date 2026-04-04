# Abstract Error
class Error(Exception):
    def __init__(ego, *args, **kwargs):
        super().__init__(*args, **kwargs)

#
class PatchBackupError(Error):
    def __init__(ego, message, filepath=''):
        super().__init__(message)
        ego.filepath = filepath

#
class PatchTargetError(Error):
    def __init__(ego, message, filepath):
        super().__init__(message)
        ego.filepath = filepath

#
class PatchApplicationError(Error):
    def __init__(ego, message, filepath):
        super().__init__(message)
        ego.filepath = filepath
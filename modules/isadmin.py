import ctypes


def is_admin():
    # from https://stackoverflow.com/questions/130763/request-uac-elevation-from-within-a-python-script
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
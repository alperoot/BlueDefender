from modules import *

buf = StringIO()
buf.write("\n1) Run system-wide scan\n\t- Includes options 3, 4, and 5\n\t- Append r to generate a report"
          "\n2) Analyze Windows Event Logs\n3) Check SMB Security Configuration"
          "\n4) Check system for vulnerabilities\n\t- Append u to update database\n9) System information\n\n"
           + hadi + " You can append 'w' to any option to only show warnings during the run (eg. 1w)\n\n" + "0) Quit\n")

# TODO: (at least try) backwards compatibility with older windows versions
# TODO: atexit

print("=========================================\n\n\tBlueDefender\n\n",
      "\tDetected OS: ", platform.system(),
      "\n\tDetected Release:", platform.release(),
      "\n\tDetected Version:", platform.version(),
      "\n\n=========================================\n")

if is_admin():
    print(neyse, "Program has admin privileges, continuing...")
else:
    print(ulan, "The app was ran with user privileges. Some parts of the app may not work properly.")
    secenek = input(ney + " Restart the app with administrator privileges? (y/n) ")

    if (secenek == 'y') or (secenek == 'yes'):
        elevate()


print(buf.getvalue())

secim = -1

while secim != '0':
    secim = input("bluedefender > ")
    if secim == '1':
        run_scan(winversion=platform.release(), silent=False)
    elif secim == '1w':
        run_scan(winversion=platform.release(), silent=True)
    elif secim == '2':
        event_analyze(silent=False)
    elif secim == '2w':
        event_analyze(silent=True)
    elif secim == '3':
        smb_check(winversion=platform.release(), silent=False)
    elif secim == '3w':
        smb_check(winversion=platform.release(), silent=True)
    elif secim == '4':
        kb_check(winversion=platform.release(), winrelease=platform.version(), silent=False)
    elif secim == '4w':
        kb_check(winversion=platform.release(), winrelease=platform.version(), silent=True)
    elif secim == '4u':
        kb_update(silent=False)
    elif (secim == '4uw') or (secim == '4wu'):
        kb_update(silent=True)
    elif secim == '4d':
        guncliste = []
        print(hadi, "Fetching currently installed Windows patches...")
        for update in get_windows_updates(filter_duplicates=True):
            if update['kb'] is not None:
                guncliste.append(update['kb'])
        kb_final(silent=False, guncliste=guncliste)
    elif secim == 'help':
        print(buf.getvalue())
    elif secim == '9':
        os.system("systeminfo")
    elif (secim == 'clear') or (secim == 'cls'):
        os.system("cls")
    else:
        if secim != '0': print("bluedefender :", secim, "- command not recognized")


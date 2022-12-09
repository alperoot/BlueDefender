import sys, colorama, ctypes, json, os, openpyxl, subprocess, re, platform
from windows_tools.updates import get_windows_updates
from .isadmin import is_admin
from termcolor import colored

colorama.init()

ulan = colored('[!]','red')
hadi = colored('[*]','cyan')
ney = colored('[?]','yellow')
neyse = colored('[!]','green')
ansizin = colored('[;)]', 'magenta')
yoo = colored('[*]', 'white')


def kb_check(winversion, winrelease, silent):

    print(hadi, "Checking if there is a newer version of the Microsoft Windows Security Bulletin file...")

    sonuc = str(subprocess.check_output('powershell.exe -ExecutionPolicy RemoteSigned -file "examples\\fetchkb.ps1"',
                                        universal_newlines=True))
    # from https://github.com/bitsadmin/wesng/blob/master/collector/collect_bulletin.ps1

    if sonuc == 'GUNCEL\n':
        print(neyse, "Bulletin file is up-to-date, continuing...")
        guncliste = []
        i = 0
        print(hadi, "Fetching currently installed Windows patches...")
        for update in get_windows_updates(filter_duplicates=True):
            if update['kb'] is not None:
                guncliste.append(update['kb'])
                i = i+1
        kb_final(silent, guncliste)

    elif sonuc == 'GUNCELLENDI\n':
        print(hadi, "Newer version of the file found!")
        secenek = input(ney + " Do you want to parse the file to update databases? This will take some time, depending on your processing power (y/n): ")
        if (secenek == 'y') or (secenek == 'Y'):
            kb_update(silent=silent)
        elif (secenek == 'n') or (secenek == 'N'):
            print(hadi, "Got it! You can run this applet as 5u to update them later, if you want (even if you're offline")
        else:
            print(hadi, "Interpreting vague answer as 'no'")
    elif sonuc == 'ISTEKHATASI':
        print(ulan, "Unknown error while checking for Microsoft Bulletin updates")
        return
    else:
        print(ulan, "Unhandled exception while running kb_check")


def kb_update(silent):
    print(ansizin, "idk man")
    # something


def kb_final(silent, guncliste):
    # print(ansizin, "burdayım")
    pattern = re.compile(r'Windows (\S+) (?:Version)?(\S+(?: Service Pack \d+)?)?(?: for (\S+))?')
    file_path = "resources\\bulletin.xlsx"
    workbook = openpyxl.load_workbook(file_path)
    sheet = workbook.active
    winversion = (str(platform.version()).split('.'))[2]
    winrelease = platform.release()

    for row in sheet.rows:
        value_os = row[6].value  # affected OS
        value_kb = row[2].value  # KB
        value_sev = row[10].value  # severity rating

        match = pattern.match(value_os)
        if match:
            release = match.group(1)
            version = match.group(2)
            system = match.group(3)
            # print(f"Expected release: {release}, received: {winrelease};
            # expected version: {version}, received: {winversion}")
            if (str(release) == str(winrelease)) and ((str(version) == str(winversion))):
                sey = False
                for i in range(0, len(guncliste)):
                    if str(guncliste[i]) == str(value_kb):
                        sey = True
                if not sey:
                    print(f"Release: {release}, Version: {version}, System: {system}, Severity: {value_sev}, KB: {value_kb}")

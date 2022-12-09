from modules.smbcheck import *
from modules.eventanalyze import *
from termcolor import colored

colorama.init()
ulan = colored('[!]','red'
                     '')
hadi = colored('[*]','cyan')
ney = colored('[?]','yellow')
neyse = colored('[!]','green')
ansizin = colored('[:)]', 'magenta')
yoo = colored('[*]', 'white')


def run_scan(winversion, silent):
    # TODO: find a better way of handling silent mode
    # TODO: scan startup, temp
    # TODO: analyze processes (eg. windows defender) - network usage
    # TODO: print current list of antivirus/antimalware processes running - https://raw.githubusercontent.com/AV1080p/AvList/master/AvList.txt
    # TODO: detect process binding/injection??

    # TODO: Check UAC level at some point
    # Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ -Name "ConsentPromptBehaviorUser"
    # If not, demonstrate how that can be exploited - ie. UAC prompt that answers itself

    if is_admin():
        print('\n' + neyse, "Program has admin privileges, continuing...")
    else:
        print(ulan, "You do not have enough permissions to run this feature\n" +
                    hadi + " Please try restarting the program with admin privileges")
        return

    warnstat, errstat = 0, 0
    warnstat_temp, errstat_temp = smb_check(winversion, silent)
    warnstat, errstat = warnstat + warnstat_temp, errstat + errstat_temp

    # more scans here

    warnstat_temp = event_analyze(silent)
    warnstat = warnstat + warnstat_temp

    warnstr = "warning" if warnstat == 1 else "warnings"
    errstr = "error" if errstat == 1 else "errors"

    print('\n' + hadi, "Scan finished with", str(warnstat), warnstr, "and", errstat, errstr, '\n')

    # From https://stackoverflow.com/questions/21944895/running-powershell-script-within-python-script-how-to-make-python-print-the-pow

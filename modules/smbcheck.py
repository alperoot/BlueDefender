import sys, colorama, subprocess, json, inspect
from .isadmin import is_admin
from termcolor import colored

colorama.init()

ulan = colored('[!]','red')
hadi = colored('[*]','cyan')
ney = colored('[?]','yellow')
neyse = colored('[!]','green')
ansizin = colored('[:)]', 'magenta')
yoo = colored('[*]', 'white')


def ps_split(line):
    return line.split(': ')[1].split("\\r")[0]
    # Useful for some powershell outputs


def smb_check(winversion, silent):
    referer = inspect.stack()[1][3]
    if not referer == 'run_scan':
        if is_admin():
            print('\n' + neyse, "Program has admin privileges, continuing...")
        else:
            print(ulan, "You do not have enough permissions to run this feature\n" +
                  hadi + " Please try restarting the program with admin privileges")
            return
    print(hadi, "Fetching SMB server configuration..." + '\n')
    warnstat = 0
    errstat = 0

    if (winversion == '10') | (winversion == '11'):
        sonuc = str(
            subprocess.check_output('powershell.exe -ExecutionPolicy RemoteSigned -file "examples\\smbchecknew.ps1"',
                                    universal_newlines=True)).split("\\n")
        # print(sonuc)
        sonuc = json.loads(sonuc[0])
        imza = sonuc["EnableSecuritySignature"]
        smb1durum = sonuc["EnableSMB1Protocol"]
        smb2durum = sonuc["EnableSMB2Protocol"]

        sonuc = str(
            subprocess.check_output('powershell.exe -ExecutionPolicy RemoteSigned -file "examples\\checknbt.ps1"',
                                    universal_newlines=True)).split("\\n")
        nbtdurum = sonuc[0]

        sonuc = str(
            subprocess.check_output('powershell.exe -ExecutionPolicy RemoteSigned -file "examples\\llmnrcheck.ps1"',
                                    universal_newlines=True)).split("\\n")
        llmnrdurum = sonuc[0]

        if not imza:
            print(ulan, "SMB signing is off. It is recommended for better security")
            warnstat = warnstat + 1
        elif imza:
            if not silent: print(neyse, "SMB signing is on")
        else:
            print(ney, "Error: Unhandled exception while checking SMB signing")
            errstat = errstat + 1
        if smb1durum:
            print(ulan, "SMBv1 is on. This older version of SMB is very insecure, and should not be used")
            warnstat = warnstat + 1
        elif not smb1durum:
            if not silent: print(neyse, "SMBv1 is off")
        else:
            print(ney, "Error: Unhandled exception while checking SMBv1")
            errstat = errstat + 1
        if not smb2durum:
            if not silent: print(yoo, "SMBv2 is off")
        elif smb2durum:
            if not silent: print(yoo, "SMBv2 is on")
        else:
            print(ney, "Error: Unhandled exception while checking SMBv2")
            errstat = errstat + 1
        if nbtdurum == 'BULUNAMADI':
            print(ulan, "Error: Unhandled exception while looking for NBT-NT registry")
            errstat = errstat + 1
        else:
            netcstat = 0
            try:
                nbtjson = json.loads(nbtdurum)
                for i in range(0, len(nbtjson)):
                    if not nbtjson[i]['NetbiosOptions'] == 0:
                        netcstat = netcstat + 1
                if netcstat:
                    print(ulan,
                          "At least 1 entry in NBT-NT configuration is non-zero. This means you have Netbios enabled, which is not recommended.")
                else:
                    if not silent: print(neyse, "Netbios is turned off/DHCP only")

            except:
                if not silent: print(neyse, "Netbios is turned off/DHCP only")

        if llmnrdurum == 'HATA':
            print(ney, "LLMNR registry entry not found. If you're not in a domain environment, this could mean it is enabled, which is a securit concern.")
            warnstat = warnstat + 1
        else:
            try:
                llmnrjson = json.loads(llmnrdurum)
                bitti = llmnrjson['EnableMultiCast']
                if str(bitti) == '0':
                    if not silent: print(neyse, "LLMNR is disabled")
                elif str(bitti) == '1':
                    print(ney, "LLMNR seems to be manually enabled. I'll just assume you know what you're doing")
                else:
                    print(ney, "LLMNR status returned", str(bitti), "and I'm not sure what that means")
                    errstat = errstat + 1
            except:
                print(ney, "LLMNR registry entry not found. If you're not in a domain environment, this could mean it is enabled, which is a securit concern.")
                warnstat = warnstat + 1

        warnstr = "warning" if warnstat == 1 else "warnings"
        errstr = "error" if errstat == 1 else "errors"

        if referer == 'run_scan':
            return warnstat, errstat
        print('\n' + hadi, "Scan finished with", str(warnstat), warnstr, "and", errstat, errstr, '\n')

    elif (winversion == '7') | (winversion == 'Vista'):
        p = subprocess.Popen('powershell.exe -ExecutionPolicy RemoteSigned -file "examples\\smbcheckold.ps1"',
                             stdout=sys.stdout)
        p.communicate()
    else:
        print(ulan, "Sorry!! Seems like this script doesn't support your Windows release yet")

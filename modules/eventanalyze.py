import os, colorama, inspect
from .isadmin import is_admin
from termcolor import colored
import win32evtlogutil
import winerror
import win32evtlog, win32security

os.system('color')
colorama.init()

ulan = colored('[!]','red')
hadi = colored('[*]','cyan')
ney = colored('[?]','yellow')
neyse = colored('[!]','green')
ansizin = colored('[:)]', 'magenta')
yoo = colored('[*]', 'white')


def cmd_split(line):
    return line.split('\t')[-1].split('\r')[0]
    # Useful for some cmd outputs


def event_analyze(silent):
    referer = inspect.stack()[1][3]
    if is_admin():
        print('')
        print(neyse, "Program has admin privileges, continuing...")
    else:
        print(ulan, "You do not have enough permissions to run this feature\n" +
                    hadi + " Please try restarting the program with admin privileges")
        return

    server = None
    logtype = "Security"
    logtype2 = "System"

    hand = win32evtlog.OpenEventLog(server, logtype)
    hand2 = win32evtlog.OpenEventLog(server, logtype2)
    flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_BACKWARDS_READ

    num = 0
    warnstat = 0
    logstat = 0
    suslist = []

    print(hadi, "Collecting Windows event log entries..." + '\n')
    while 1:
        objects = win32evtlog.ReadEventLog(hand,flags,0)
        objects2 = win32evtlog.ReadEventLog(hand2,flags,0)
        if not objects:
            break
        for object in objects:
            msg = win32evtlogutil.SafeFormatMessage(object, logtype)
            if object.EventID == 4625:  # failed logon
                preamble = '[' + object.TimeGenerated.Format() + ']'
                preamble = colored(preamble, 'white')
                logstat = logstat + 1
                try:
                    msg1 = msg.split('\n')
                    sourceip = cmd_split(msg1[26])
                    if (sourceip == '::1') or (sourceip == '127.0.0.1'):
                        sourceip = 'localhost'
                        if not silent:
                            print(preamble, msg1[0])
                            print(yoo, msg1[12])  # Line 12 is user
                            print(yoo, msg1[22])  # Line 22 is the process that called it
                            print(yoo, "Source IP is", cmd_split(msg1[26]), "(localhost)")
                            print("")
                    else:
                        print(preamble, msg1[0])
                        print(yoo, msg1[12])  # Line 12 is user
                        print(yoo, msg1[22])  # Line 22 is the process that called it
                        print(ulan, "Source IP is", cmd_split(msg1[26]), "(NOT localhost!!)") # Line 26 is source IP
                        suslist.append(cmd_split(msg1[26]))
                        warnstat = warnstat + 1
                        print("")
                    # print(hadi, msg1[26]) # Line 26 is source IP address
                    # print(hadi, msg1[27]) # not sure about this one
                except UnicodeError:
                    print(ulan, "Description of event couldn't be read due to a Unicode problem")
            elif object.EventID == 1102:    # audit cleared
                preamble = '[' + object.TimeGenerated.Format() + ']'
                preamble = colored(preamble, 'red')
                msg1 = msg.split('\n')
                print(preamble, "Event log was cleared")
                print(ulan, msg1[0])
                print(ulan, "This is usually indicative of an attacker trying to cover their tracks")
                warnstat = warnstat + 1
        for object in objects2:
            if not objects2:
                break
            msg = win32evtlogutil.SafeFormatMessage(object, logtype2)
            if object.EventID == 7045:    # remote service created - this is in SYSTEM
                preamble = '[' + object.TimeGenerated.Format() + ']'
                preamble = colored(preamble, 'red')
                msg1 = msg.split('\n')
                print(preamble, "A remote service was created")
                print(ulan, msg1[0])
                print(ulan, "This could indicate PSEXEC being used to access this computer remotely")
                warnstat = warnstat + 1
        num = num + len(objects)

    susstat = 0

    if warnstat:
        print(hadi, "Analyzing successful login information...")
        while 1:
            objects = win32evtlog.ReadEventLog(hand, flags, 0)
            if not objects:
                break
            for object in objects:
                msg = win32evtlogutil.SafeFormatMessage(object, logtype)
                if object.EventID == 4624:  # successful logon
                    preamble = '[' + object.TimeGenerated.Format() + ']'
                    preamble = colored(preamble, 'red')
                    logstat = logstat + 1
                    try:
                        msg1 = msg.split('\n')
                        sourceip = cmd_split(msg1[26]) # line 26 is source IP
                        for i in range(0, len(suslist)):
                            if suslist[i] == sourceip:
                                print(preamble, "Unknown login from IP", suslist[i])
                                print(ulan, msg1[0])
                                print(ulan, msg1[12])  # Line 12 is user
                                print(ulan, msg1[22])  # Line 22 is the process that called it
                                print(ulan, "Contact your system administrator if the IP address is not familiar")
                                susstat = susstat + 1
                                warnstat = warnstat + 1
                        if not ((sourceip == '::1') or (sourceip == '127.0.0.1')):
                            print(preamble, "Remote login from IP", sourceip)
                            print(ulan, msg1[0])
                            print(ulan, msg1[12])  # Line 12 is user
                            print(ulan, msg1[22])  # Line 22 is the process that called it
                            warnstat = warnstat + 1
                    except UnicodeError:
                        print(ulan, "Description of event couldn't be read due to a Unicode problem")
            num = num + len(objects)

    if not susstat:
        print(neyse, "Doesn't seem like any of the login attempts were successful, but still do keep an eye out!\n")

    warnstr = "warning" if warnstat == 1 else "warnings"
    logstr = "invalid logon" if logstat == 1 else "invalid logons"
    numstr = "entry" if logstat == 1 else "entries"

    if referer == 'run_scan':
        return warnstat

    print(hadi, "Analyzed", num, "event log", numstr)
    print(hadi, "Analysis ended with", logstat, logstr, "and", warnstat, warnstr)

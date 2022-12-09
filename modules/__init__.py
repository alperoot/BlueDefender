import sys, colorama, ctypes, subprocess, json, inspect
import os, sys, platform, colorama, ctypes, subprocess, json, psutil
from windows_tools.updates import get_windows_updates
from termcolor import colored
from io import StringIO
from elevate import elevate

from .sysscan import *
from .eventanalyze import event_analyze
from .smbcheck import smb_check
from .isadmin import is_admin
from .kbcheck import *


os.system('color')
colorama.init()

ulan = colored('[!]','red')
hadi = colored('[*]','cyan')
ney = colored('[?]','yellow')
neyse = colored('[!]','green')
ansizin = colored('[:)]', 'magenta')
yoo = colored('[*]', 'white')
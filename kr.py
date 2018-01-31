import string
import os
import re
import sys
from colorama import Fore, Back, Style

# ++++++++++++++++++++++++++++++++++++++++++++++++
# READ KEY FROM FILE|ALSO CAN READ MULTIPLE KEYS +
# ++++++++++++++++++++++++++++++++++++++++++++++++

class kre:
    tkeys = []

    def ckfile(self):
        if (os.path.isfile('api.key')):
            kfil = open('api.key','r')
            linZ = kfil.readlines()
            for line in linZ[0:]:
                pline = line.split('\n')
                self.tkeys.append(pline[0])
            if (len(self.tkeys) == 0):
                kstat = False
            else:
               kstat = True
        else:
            kstat = False
        return kstat

    def klist(self):
        if (self.ckfile()):
            print (Fore.GREEN+'[*] Printing API-KEYS:')
            for length in range(len(self.tkeys)):
                print (str(length)+') '+self.tkeys[length])   # also can use repr(lenght)
        else:
            print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)

    def kadd(self,initapi):
        with open('api.key','a') as kfil:
            kfil.write(initapi+'\n')
            kfil.close()
        print (Fore.GREEN+'[*] Key Added'+Style.RESET_ALL)

    def kdel(self,dapi):
        kfil = open('api.key','r')
        linZ = kfil.readlines()
        kfil.close()
        kfil = open('api.key','w')
        for line in linZ:
            if (line != dapi+'\n'):
                kfil.write(line)
        kfil.close()
        print (Fore.GREEN+'[*] Key Deleted'+Style.RESET_ALL)

    def chokey(self):
        print (Fore.GREEN+'\n[*] Printing API-KEYS:')
        for length in range(len(self.tkeys)):
            print (str(length)+') '+self.tkeys[length])
        keyindex = int(raw_input(Fore.YELLOW+'\n[?] Enter the index number of key that you want to be used: '))
        return self.tkeys[keyindex]

    def help_menu(self):
        print (Fore.YELLOW+'''\nThis is help menu for API-KEY functions.
The API-KEY is required to search shodan. You can search shodan without API-KEY but there are some limits
like "YOU CAN NOT USE ANY SPECIFIC FILTER IN YOUR SEARCH WITHOUT API-KEY" and some other limits.
You can list your Keys, Delete any Key or add new Key in API-KEY file.
\nTo list Keys:
python zkshs.py --kf list   - - -   This will list all Keys that are inside Key file.
\nTo add new Key:
python zkshs.py --kf add --api YOUR_API_KEY   - - -   This will add the Key inside Key file.
\nTo delete Key:
python zkshs.py --kf del --api YOUR_API_KEY   - - -   This will delete the Key from Key file.
\n<< Before you do anything, Its IMPORTANT to add at least one API-KEY to the Key file. >>\n'''+Style.RESET_ALL)
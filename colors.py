#!/usr/bin/env python

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''

print bcolors.WARNING + 'Warning: This is the warning text' + bcolors.ENDC
print bcolors.HEADER + 'Header: Header text' + bcolors.ENDC
print bcolors.FAIL + '[!] Error: This is error text' + bcolors.ENDC

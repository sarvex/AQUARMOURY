#!/usr/bin/env python

"""
[!] Reference: https://github.com/silentbreaksec/Throwback/blob/master/Python/tbMangler.py
[+] Usage: python StringMangler.py [operation] [string or filename]

   [operation]          - encode or decode 
   [string or filename] - a string or filename to encode or decode
   
   Example: python StringMangler.py encode StringIWantToHide!
            python StringMangler.py decode {2,37,35,56,63,54,24,6,48,63,37,5,62,25,56,53,52,112}
            python StringMangler.py encode /path/to/file/with/a/bunch/of/strings/to/encode
            
   NOTE: From the command line, the script doesn't interpret ' properly, but in a file it is interpreted correctly.
"""


import sys, os, operator


# CAN BE CHANGED BUT MUST MATCH WRAITH CONFIG FILE
KEY = 'W'


def encodeString(clearText):
    
    cipherText = '{'
    
    for a in range(0,len(clearText)):
        c = ord(clearText[a])
        k = ord(KEY)
        cipherText += str(operator.xor(c, k) % 255)
        if a < (len(clearText)-1): cipherText += ','
    
    cipherText += '}'
    return cipherText


def decodeString(cipherText):
    
    cipherText = cipherText.replace('{', '')
    cipherText = cipherText.replace('}', '')
    cipherText = cipherText.split(',')
    clearText = ''
    
    for a in range(0, len(cipherText)):
        c = int(cipherText[a])
        k = ord(KEY)
        clearText += chr(operator.xor(c, k) % 255)
    
    return clearText

    
def main():
    try:
        if len(sys.argv) == 3:
            operation = sys.argv[1]
            string = sys.argv[2]
        else:
            raise
    except:
        print(__doc__)
        sys.exit(0)
    
    todo = None
    
    if operation == 'encode':
        
        if os.path.isfile(string): todo = open(string, 'r').readlines()
        else: todo = string
        
        if type(todo).__name__ == 'list':
            for do in todo:
                do = do.replace('\n', '')
                do = do.replace('\r', '')
                print("\n%s -> %s\n" % (do, encodeString(do)))
        else:
            todo = todo.replace('\n', '')
            todo = todo.replace('\r', '')
            print("\n%s -> %s\n" % (todo, encodeString(todo)))
    
    elif operation == 'decode':
        
        if os.path.isfile(string): todo = open(string, 'r').readlines()
        else: todo = string
        
        if type(todo).__name__ == 'list':
            for do in todo:
                do = do.replace('\n', '')
                do = do.replace('\r', '')
                print("\n%s -> %s\n" % (do, decodeString(do)))
        else:
            todo = todo.replace('\n', '')
            todo = todo.replace('\r', '')
            print("\n%s -> %s\n" % (todo, decodeString(todo)))     
    else:
        print(__doc__)
        sys.exit(0)


if __name__ == '__main__':
    main()
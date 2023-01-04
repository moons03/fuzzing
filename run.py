import requests
import argparse
import textwrap
import threading
import os
import re
from collections import namedtuple

class fuzz:
    def __init__(self, args) -> None:
        self.args = args
        # regex = re.compile('.*{[a-zA-Z]}.*')
        # for _ in args.wordlist.split(','):
        #     if regex.match(_) == None:
        #         break
        
        self.signlist = args.wordlist.split(',')
        self.wordListArray = args.wordlist.split(',')
        self.wordListFile = args.wordlist.split(',')
        
        for i in range(len(self.signlist)):
            
            self.signlist[i] = namedtuple('Signlist', 'file, sign')
            '''
                namedtuple('signlist', 'file, sign')
            '''
            self.signlist[i].file = self.wordListArray[i].split(':')[0]
            try:
                self.signlist[i].sign = self.wordListArray[i].split(':')[1]
            except IndexError:
                self.signlist[i].sign = '{}'        # deflaot sign
            
            self.wordListFile[i] = open(self.signlist[i].file , 'r')
            self.statuscode = args.statusCode.split(',') 
            '''
            status code
            '''
        for i in range(len(self.signlist)):
            print(self.signlist[i].file, self.signlist[i].sign)
        
    def changeSignature(self):
        pass

    def run(self):
        mark = ['' for i in range(len(self.signlist))]
        while True:
            for i in range(len(self.signlist) - 1):
                mark[i] = self.wordListFile[i].readline().strip()
                if mark[i] == '':
                    self.wordListFile[i].seek(0)
                    mark[i + 1] = self.wordListFile[i + 1].readline().strip()
            if ''.join(mark) == '':
                break
            payload = args.url
            for i in range(len(self.signlist)): # here 
                payload = payload.replace(self.signlist[i].sign, mark[i]).strip()

            attack_thread = threading.Thread(target=self.attack, args=(payload,))
            attack_thread.start()

    # multi threading
    def attack(self, payload):
        #print(payload)
        res = requests.get(url=payload)
        if str(res.status_code) in self.statuscode:
            print(f'{payload:45s} [{res.status_code}] [{len(res.text):^5d}]\n', end='')
        else:
            print(f'--{payload:45s} [{res.status_code}] [{len(res.text):^5d}]\n', end='')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
            description = 'FUZZING Machine',
            epilog='''Example:
            run.py -w /usr/share/wordlist/dirb/common.txt -u http://google.com/{}
            run.py -X POST -w /usr/share/wordlist/dirb/common.txt -u http://google.com/ -d usrid=1&usrpw={} --urlencode
            '''
        )

    parser.add_argument('-w', '--wordlist', help='word list', default="digits.txt:{2},digits_copy.txt:{0},digits1.txt:{1}")

    # http options
    parser.add_argument('-u', '--url', help='target url', default="http://google.com/{0}{1}{2}")
    parser.add_argument('-H', '--header', help="http header")
    parser.add_argument('-d', '--data', help='POST Data')
    parser.add_argument('-X', '--method', help='http Method', default='GET')
    parser.add_argument('-sf','--statusCode', help='http status code filter ex) 200,404', default='200,204,301,302,307,401,403,405,500')

    args = parser.parse_args()

    Fuzz = fuzz(args)
    Fuzz.run()
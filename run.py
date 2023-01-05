import requests
import argparse
import textwrap
import threading
import os
import re
import string
from collections import namedtuple

class fuzz:
    def __init__(self, args) -> None:
        self.args = args
        self.args.method = self.args.method.lower()
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
                if self.signlist[i].sign == '':
                    raise IndexError
            except IndexError:
                self.signlist[i].sign = '{}'        # deflaot sign
            try:
                self.signlist[i].exp = self.wordListArray[i].split(':')[2]
                if self.signlist[i].exp == '':
                    raise IndexError
            except IndexError:
                self.signlist[i].exp = '$'        # deflaot exp
            
            self.wordListFile[i] = open(self.signlist[i].file , 'r')
            self.statuscode = args.statusCode.split(',') 
            '''
            status code
            '''
        for i in range(len(self.signlist)):
            print(f'{self.signlist[i].file}<-{self.signlist[i].sign}')

    def run(self):
        print(self.args.header)
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
                mark[i] = eval(self.signlist[i].exp.replace('$', 'mark[i]'))
                payload = payload.replace(self.signlist[i].sign, str(mark[i])).strip()

            attack_thread = threading.Thread(target=self.attack, args=(payload,))
            attack_thread.start()

    # multi threading
    def attack(self, payload):
        result = ''
        res = eval(f"requests.{self.args.method}(url=payload, data='{self.args.data}', headers='{self.args.header}')") # for scalability
        
        # check http status code
        if self.statuscode and str(res.status_code) in self.statuscode:
            result += f'[{res.status_code}] [{len(res.text):^5d}]'    
            
        # check flag
        if self.args.flag != '':
            result += f' [flag: '
            if res.text.find(self.args.flag) != -1:
                result += 'O]'
            else: 
                result += 'X]'
        if result != '':
            result = f'{payload:45s}' + result
            print(f'{result}\n', end='') # end = '\n' then it have multi thraeding problem

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
            description = 'FUZZING Machine',
            epilog='''Example:
            run.py -w /usr/share/wordlist/dirb/common.txt -u http://google.com/{}
            run.py -X POST -w /usr/share/wordlist/dirb/common.txt -u http://google.com/ -d usrid=1&usrpw={} --urlencode
            '''
        )

    parser.add_argument('-w', '--wordlist', help='word list', default="digits.txt:{0}:,digits1.txt:{1}")

    # http options
    parser.add_argument('-u', '--url', help='target url', default="http://google.com/{0}{1}")
    parser.add_argument('-H', '--header', help="http header", default='')
    parser.add_argument('-d', '--data', help='POST Data', default='')
    parser.add_argument('-X', '--method', help='http Method', default='GET')
    parser.add_argument('-sf','--statusCode', help='http status code filter ex) 200,404', default='200,204,301,302,307,401,404,403,405,500')
    parser.add_argument('--timeout', type=int, help='requests', default=10)
    parser.add_argument('-f', '--flag', help='check it is included', default='')
    
    args = parser.parse_args()

    Fuzz = fuzz(args)
    Fuzz.run()
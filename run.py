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
        
        self.signlist = namedtuple('Signlist', 'file, sign')
        '''
            namedtuple('signlist', 'file, sign')
        '''
        self.signlist.file = args.wordlist.split(':')[0]
        try:
            self.signlist.sign = args.wordlist.split(':')[1]
        except IndexError:
            self.signlist.sign = '{}'
        
        self.wordlist = open(self.signlist.file , 'r')
        self.statuscode = args.statusCode.split(',') 
        '''
        status code
        '''
        
    def changeSignature(self):
        pass

    def run(self):
        data = self.wordlist.readline()

        while data != '':
            payload = args.url
            payload = payload.replace(self.signlist.sign, data).strip()

            attack_thread = threading.Thread(target=self.attack, args=(payload,))
            attack_thread.start()

            data = self.wordlist.readline()

    # multi threading
    def attack(self, payload):
        #print(payload)
        res = requests.get(url=payload)
        if str(res.status_code) in self.statuscode:
            print(f'{payload:45s} [{res.status_code}] [{len(res.text):^5d}]\n', end='')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
            description = 'FUZZING Machine',
            epilog='''Example:
            run.py -w /usr/share/wordlist/dirb/common.txt -u http://google.com/{}
            run.py -X POST -w /usr/share/wordlist/dirb/common.txt -u http://google.com/ -d usrid=1&usrpw={} --urlencode
            '''
        )

    parser.add_argument('-w', '--wordlist', help='word list', default="common.txt:{1}")

    # http options
    parser.add_argument('-u', '--url', help='target url', default="http://google.com/{}")
    parser.add_argument('-h', 'header', help="http header")
    parser.add_argument('-d', '--data', help='POST Data')
    parser.add_argument('-X', '--method', help='http Method', default='GET')
    parser.add_argument('-sf','--statusCode', help='http status code filter ex) 200,404', default='200,204,301,302,307,401,403,405,500')

    args = parser.parse_args()

    Fuzz = fuzz(args)
    Fuzz.run()
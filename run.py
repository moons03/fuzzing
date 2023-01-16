import requests
import argparse
import textwrap
import threading
import os
import re
import string
import sys
from urllib.parse import urlparse
from collections import namedtuple

def urlcheck(url):
    check = urlparse(url)
    if check.scheme == '':
        check = check._replace(scheme = 'http', netloc = check.path, path = '')
    return check.geturl()
class Fuzz:
    def __init__(self, args) -> None:
        self.args = args
        self.args.method = self.args.method.lower()
        
        # summary
        self.Packet = 0
        self.missingPacket = list()
        
        #url parser
        self.args.url = urlcheck(self.args.url)
        print(self.args.url)
        # regex = re.compile('.*{[a-zA-Z]}.*')
        # for _ in args.wordlist.split(','):
        #     if regex.match(_) == None:
        #         break
        
        self.signlist = args.wordlist.split(',')
        self.wordListArray = args.wordlist.split(',')
        self.wordListFile = args.wordlist.split(',')
        
        # set output file
        if self.args.remoteName != '' or self.args.outfile == True:
            if self.args.outfile == True:
                # file  already existed
                if os.path.exists('fuzz.txt'):
                    with open('fuzz.txt', 'r') as f:
                        for line in f.readlines():
                            if line.strip() != '':
                                print('"fuzz.txt" File already existed')
                                sys.exit()
                fname = 'fuzz.txt'
            else:
                fname = self.args.remoteName

            self.file = open(file=fname, mode='w')
        else:
            self.file = None

        # manage threads
        self.threads = list()
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

    def exit(self, e=''):
        print(e)
        if len(self.missingPacket) != 0:
            self.stdout('\n' + '-' * 30 + '{Missing Pachket}' + '-' * 30 + '\n')
        print(f'{self.Packet}/{self.Packet - len(self.missingPacket)}')
        for line in self.missingPacket:
            self.stdout(line)
        if self.file != None:
            self.file.close()

    def stdout(self, string, end='\n'):
        if self.file == None:
            print(string, end=end)
        else:
            self.file.write(string)

    def run(self):
        print(self.args.header)
        mark = ['' for i in range(len(self.signlist))]
        while True:
            
            mark[0] = self.wordListFile[0].readline().strip()
            
            for i in range(len(self.signlist)):
                # check every file reader 
                if mark[i] == '':
                    self.wordListFile[i].seek(0)
                    mark[i] = self.wordListFile[i].readline().strip()
                    # not last mark is finish
                    if i < len(self.signlist) - 1:
                        mark[i + 1] = self.wordListFile[i + 1].readline().strip()
                    else:
                        return 0
            
            # formating payload 
            payload = self.args.url
            for i in range(len(self.signlist)): # here 
                
                try:
                    # add rule
                    mark[i] = eval(self.signlist[i].exp.replace('$', 'mark[i]'))
                    payload = payload.replace(self.signlist[i].sign, str(mark[i])).strip()
                    self.args.data = self.args.data.replace(self.signlist[i].sign, str(mark[i]))
                    self.args.header = self.args.header.replace(self.signlist[i].sign, str(mark[i]))
                    self.args.timeout = self.args.timeout.replace(self.signlist[i].sign, str(mark[i]))
                except Exception as e:
                    print(e)
                    exit()

            attack_thread = threading.Thread(target=self.attack, args=(payload,))
            attack_thread.daemon = True # daemon thread
            attack_thread.start()
            self.threads.append(attack_thread)
            if threading.active_count() > self.args.thread:
                attack_thread.join()

    # multi threading
    def attack(self, payload):
        self.Packet += 1
        result = ''
        try:
            res = eval(f"requests.{self.args.method}(url=payload, data='{self.args.data}', headers='{self.args.header}', timeout={self.args.timeout})") # for scalability
        except requests.Timeout:
            try:
                res = eval(f"requests.{self.args.method}(url=payload, data='{self.args.data}', headers='{self.args.header}', timeout={self.args.timeout})")
            except requests.Timeout:
                self.missingPacket.append(payload +'' if self.args.data == '' else self.args.data)
                return 
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
            self.stdout(f'{result}\n', end='') # end = '\n' then it have multi thraeding problem

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
            description = 'FUZZING Machine',
            epilog='''Example:
            run.py -w /usr/share/wordlist/dirb/common.txt -u http://google.com/{}
            run.py -X POST -w /usr/share/wordlist/dirb/common.txt -u http://google.com/ -d usrid=1&usrpw={} --urlencode
            '''
        )

    parser.add_argument('-w', '--wordlist', help='word list', default="digits.txt:{0}:$+f'({en($)})'")
    parser.add_argument('-o', '--outfile', action='store_true', help='Wirte output to a file name as the remoted name')
    parser.add_argument('-O', '--remoteName', help='Write to file instead of stdout', default='')

    # http options
    parser.add_argument('-u', '--url', help='target url', default="google.com/{0}/{1}/{2}")
    parser.add_argument('-H', '--header', help="http header", default='')
    parser.add_argument('-d', '--data', help='POST Data', default='')
    parser.add_argument('-X', '--method', help='http Method', default='GET')
    parser.add_argument('-sf','--statusCode', help='http status code filter ex) 200,404', default='200,204,301,302,307,401,404,403,405,500')
    parser.add_argument('--timeout', help='requests time out', default = '1')
    parser.add_argument('-f', '--flag', help='check it is included', default='')
    
    parser.add_argument('-t', '--thread', type=int, help='max thread count', default=100)
    
    args = parser.parse_args()
    
    fuzz = Fuzz(args)
    fuzz.run()
    for thread in fuzz.threads:
        thread.join()
    fuzz.exit()
    # os.system("pause")
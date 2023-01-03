import requests
import argparse
import textwrap
import os

class fuzz:
    def __init__(self, args) -> None:
        self.args = args
        self.wordlist = open(args, 'r')
        while self.wordlist != None:
            print(self.wordlist.readline())
            
    def run():
        pass
    
if __name__ == '__main__'():
    parser = argparse.ArgumentParser(
            description = 'FUZZING Machine',
            epilog='''Example:
            run.py -w /usr/share/wordlist/dirb/common.txt -u http://google.com/{1}
            run.py -X POST -w /usr/share/wordlist/dirb/common.txt -u http://google.com/ -d usrid=1&usrpw={1} --urlencode
            '''
        )
    
    parser.add_argument('-w', help='word list', default="/usr/share/wordlists/dirb/common.txt")
    
    # http options
    parser.add_argument('-u', '-url', help='target url', default="http://google.com/{}")
    parser.add_argument('-d', '--data', help='POST Data')
    args = parser.parse_args()
    
    Fuzz = fuzz(args)
    Fuzz.run()
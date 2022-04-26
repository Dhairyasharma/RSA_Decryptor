import argparse
import sys
from Crypto.Util.number import inverse,long_to_bytes
from factordb.factordb import FactorDB

#intializing arguments
parser = argparse.ArgumentParser(description="RSA can be vulnerable ;)")
parser.add_argument('-n','--number',required=True,metavar='', help="Value of n")
parser.add_argument('-e','--exp',required=True,metavar='',help="Value of e")
parser.add_argument('-c','--cipher',required=True,metavar='',help='Value of Cipher')
group = parser.add_mutually_exclusive_group()
group.add_argument('-H','--hex', action='store_true',help='Use this if value of n,e,c are in hex')
group.add_argument('-D','--decimal',action='store_true',help='Use this if value of n,e,c are in decimal')
args = parser.parse_args()

def banner():
    ban = '''
    ____  _____ ___       ____                 __              __
   / __ \/ ___//   |     / __ \___  __________/ /___  ______  / /_____  _____
  / /_/ /\__ \/ /| |    / / / / _ \/ ___/ ___/ __/ / / / __ \/ __/ __ \/ ___/
 / _, _/___/ / ___ |   / /_/ /  __/ /__/ /  / /_/ /_/ / /_/ / /_/ /_/ / /
/_/ |_|/____/_/  |_|  /_____/\___/\___/_/   \__/\__, / .___/\__/\____/_/
                                               /____/_/                  '''

    print(ban)
def get_pq(n):
    f = FactorDB(n)
    f.connect()
    value = f.get_factor_list()
    if len(value) != 2:
        print('\033[91m [-] Factor of n is not in database :( \033[00m')
        sys.exit()
    return value[0],value[1]

if __name__ == '__main__':

    banner()

    if args.hex:
        n = int(args.number,16)
        c = int(args.cipher,16)
        e = int(args.exp,16)
    elif args.decimal:
        n = int(args.number)
        c = int(args.cipher)
        e = int(args.exp)
    else:
        print('Please Provide [-H | -D] according to n,e,c')
        sys.exit()
    p,q = get_pq(n)


    phi = (p-1)*(q-1)
    
    print(f'[+] Value of Phi = {phi}')


    d = inverse(e,phi)

    
    print(f'[+] Value of d = {d}')
    
    m = pow(c,d,n)

    print(f'[+] Message Retrieved: \033[92m {long_to_bytes(m).decode()} \033[00m')


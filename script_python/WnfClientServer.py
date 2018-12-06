"""

Copyright (c) 2018 Gabrielle Viala. All Rights Reserved.
https://blog.quarkslab.com/author/gwaby.html

"""

from wnfcom import WnfCom
import argparse
import sys


############### MAIN ###############


if __name__ == "__main__":
    argParser = argparse.ArgumentParser(description="")
    argParser.add_argument("WNF_NAME", nargs='?', type=str, help="state name")
    args = argParser.parse_args()

    wnfserver = WnfCom()    
    if args.WNF_NAME:
        if not wnfserver.SetStateName(args.WNF_NAME):
            sys.exit("[Error] State name unknown.")
        wnfserver.Listen() 
    else:
        wnfserver.CreateServer()
        wnfserver.Write()
    
        while True:
            try:
                Data = input(">")
            except KeyboardInterrupt as e:
                break
            wnfserver.Write(Data.encode())


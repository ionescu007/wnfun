"""

Copyright (c) 2018 Gabrielle Viala. All Rights Reserved.
https://blog.quarkslab.com/author/gwaby.html

"""

from win32api import (
    GetCurrentProcess, 
    RegOpenKeyEx, 
    RegEnumValue, 
    RegQueryValueEx, 
    RegCloseKey
)
from win32con import (
    TOKEN_ALL_ACCESS, 
    HKEY_LOCAL_MACHINE, 
    KEY_READ
)
import win32security
from pywintypes import error
from struct import unpack
from enum import Enum
from hexdump import hexdump
import ctypes
import argparse
import sys

from WellKnownWnfNames import g_WellKnownWnfNames # comment this if you don't have the file



ZwQueryWnfStateData = ctypes.windll.ntdll.ZwQueryWnfStateData
ZwUpdateWnfStateData = ctypes.windll.ntdll.ZwUpdateWnfStateData
ZwQueryWnfStateNameInformation = ctypes.windll.ntdll.ZwQueryWnfStateNameInformation

WNF_STATE_KEY = 0x41C64E6DA3BC0074

STATUS_OPERATION_FAILED = 0xc0000001


class WNF_STATE_NAME_LIFETIME(Enum):
    WnfWellKnownStateName = 0x0
    WnfPermanentStateName = 0x1
    WnfPersistentStateName = 0x2
    WnfTemporaryStateName = 0x3

class WNF_DATA_SCOPE(Enum):
    WnfDataScopeSystem = 0x0
    WnfDataScopeSession = 0x1
    WnfDataScopeUser = 0x2
    WnfDataScopeProcess = 0x3
    WnfDataScopeMachine = 0x4


class WNF_STATE_NAME_INFORMATION(Enum):
    WnfInfoStateNameExist = 0x0
    WnfInfoSubscribersPresent = 0x1
    WnfInfoIsQuiescent = 0x2

class WNF_STATE_NAME_bits(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Version", ctypes.c_ulonglong, 4),
        ("NameLifetime", ctypes.c_ulonglong, 2),
        ("DataScope", ctypes.c_ulonglong, 4),
        ("PermanentData", ctypes.c_ulonglong, 1),
        ("Unique", ctypes.c_ulonglong, 53),
        ("value", ctypes.c_ulonglong)
    ]


class WNF_STATE_NAME_INTERNAL(ctypes.Union):
    _fields_ = [("b", WNF_STATE_NAME_bits),
                ("value", ctypes.c_ulonglong)]


WnfDataScopeStrings = [
    "System",
    "session",
    "User",
    "Process",
    "Machine"
]

g_LifetimeKeyNames = [
    "SYSTEM\\CurrentControlSet\\Control\\Notifications",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Notifications",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\VolatileNotifications"
]

WnfLifetimeStrings = [
    "Well-Known",
    "Permanent",
    "Volatile",
    "Temporary"
]

def DumpWnfData(WnfName, Data, DumpSd, DumpData):
    assert(WnfName != 0)
    MaxSize = "?"
    sd = None
    if Data != None:
        try:
            sd = win32security.SECURITY_DESCRIPTOR(Data)
        except:
            print("\n[Error] Could not create a security descriptor out of the data for {:x}\n".format(WnfName))

        if sd != None:
            if not sd.IsValid():
                print("[Error] Registry security descriptor invalid for {:x}\n".format(WnfName))
                MaxSize = 0
                sd = None
            SdSize = sd.GetLength()
            MaxSize = unpack("L", Data[SdSize:SdSize+4])[0]

    return PrintWnfRuntimeStatus(WnfName, sd, DumpSd, MaxSize, DumpData)

def ReadWnfData(StateName):
    changeStamp = ctypes.c_ulong(0)
    dataBuffer = ctypes.create_string_buffer(4096)
    bufferSize = ctypes.c_ulong(ctypes.sizeof(dataBuffer))  
    StateName = ctypes.c_longlong(StateName)
    res = ZwQueryWnfStateData(ctypes.byref(StateName), 
        0, 0, 
        ctypes.byref(changeStamp), 
        ctypes.byref(dataBuffer), 
        ctypes.byref(bufferSize)
    )
    readAccess = 0 if res !=0 else 1
    bufferSize =  ctypes.c_ulong(0) if res !=0 else bufferSize
    return readAccess, changeStamp.value, dataBuffer, bufferSize.value


def CheckWriteAccess(StateName):
    StateName = ctypes.c_longlong(StateName)
    status = ZwUpdateWnfStateData(ctypes.byref(StateName), 0, 0, 0, 0, -1, True)
    status = ctypes.c_ulong(status).value
    assert(status != 0) # We really changed something... Not good O.O'

    return False if status != STATUS_OPERATION_FAILED else True


def QueryWnfInfoClass(StateName, infoClassName):
    exist = ctypes.c_ulong(2)
    StateName = ctypes.c_longlong(StateName)
    InfoValue = WNF_STATE_NAME_INFORMATION[infoClassName].value
    

    status = ZwQueryWnfStateNameInformation(ctypes.byref(StateName), InfoValue, 0, ctypes.byref(exist), ctypes.sizeof(exist))
    status = ctypes.c_ulong(status).value    
    if status != 0:
        print("[Error] Could not query subscribers: : 0x{:x}".format(status))
    return exist.value


def GetWnfName(value):
    try:
        name = list(g_WellKnownWnfNames.keys())[list(g_WellKnownWnfNames.values()).index(value)]
    except:
        name = ""
    return name


def CheckInternalName(Name):
    if Name.b.NameLifetime > len(WnfLifetimeStrings):
        return False
    if Name.b.DataScope > len(WnfDataScopeStrings):
        return False
    return True


def PrintWnfRuntimeStatus(StateName, CheckSd, DumpSd, MaxSize, DumpData):
    exists = 2
    read, changeStamp, dataBuffer, bufferSize = ReadWnfData(StateName)

    write =  CheckWriteAccess(StateName)
    if write:
        # see if anyone is listening for notifications on this state name.
        exists = QueryWnfInfoClass(StateName, 'WnfInfoSubscribersPresent')
    
    internalName =  WNF_STATE_NAME_INTERNAL()
    internalName.value = StateName ^ WNF_STATE_KEY

    if not CheckInternalName(internalName):
        return False

    if internalName.b.NameLifetime == WNF_STATE_NAME_LIFETIME['WnfWellKnownStateName'].value:
        name = GetWnfName(StateName)
        if name == "":
            char3 = format(internalName.b.Unique >> 37 & 0xff, 'c')
            char4 = format(internalName.b.Unique >> 45 & 0xff, 'c')
            char3 = char3 if char3.isprintable() else " "
            char4 = char4 if char4.isprintable() else " "
            
            name ="{:c}{:c}{}{}.{:0>3} 0x{:x}".format(
                internalName.b.Unique >> 21 & 0xff,
                internalName.b.Unique >> 29 & 0xff,
                char3,
                char4,
                internalName.b.Unique & 0xFFFFF,
                StateName)
    else:
        name = "0x{:x}".format(StateName)
    print("| {:<64}| {} | {} | {} | {} | {} | {:^7} | {:^7} | {:^7} |".format(
            name,
            WnfDataScopeStrings[internalName.b.DataScope][0],
            WnfLifetimeStrings[internalName.b.NameLifetime][0],
            'Y' if internalName.b.PermanentData else 'N',
            ("RW" if write else "RO") if read else ("WO" if write else "NA"),
            'A' if exists == 1 else 'U' if exists == 2 else 'I',
            bufferSize,
            MaxSize,
            changeStamp
        ))  
    
    if DumpSd != False and CheckSd != None:
        strSd = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
            CheckSd, win32security.SDDL_REVISION_1, 
            win32security.DACL_SECURITY_INFORMATION | 
            win32security.SACL_SECURITY_INFORMATION | 
            win32security.LABEL_SECURITY_INFORMATION)
        print("\n\t{}".format(strSd))

    if DumpData != False and read != False and bufferSize != 0:
        print("\n")
        hexdump(dataBuffer.raw[0:bufferSize])
        print("\n")

    return True

def FormatStateName(WnfName):
    try:
        StateName = "{:x}".format(g_WellKnownWnfNames[WnfName.upper()])   
    except:
        if len(WnfName)>2 and WnfName[1] == 'x':
            WnfName = WnfName[2:]
        StateName = WnfName
    for _ in range(len(StateName),16):
        StateName = "0"+StateName
    
    try:
        int(StateName, 16)
    except:
        StateName = "-1"
    return StateName

#########################################################################################

#### Displays information on all non-temporary state names
def DumpWnfNames(ShowSd, ShowData):
    for i in range(0,len(g_LifetimeKeyNames)):
        reghandle = None
        try:
            reghandle = RegOpenKeyEx(
                HKEY_LOCAL_MACHINE,
                g_LifetimeKeyNames[i],
                0,
                KEY_READ)
        except Exception:
            print("[Error] Could not open root key: {}".format(g_LifetimeKeyNames[i]))
            return False

        print("\n| WNF State Name [{:<10} Lifetime]                            "
                    "| S | L | P | AC | N | CurSize | MaxSize | Changes |".format(WnfLifetimeStrings[i]))
        print("-"*118)

        i = 0
        while 1:
            try:
                name, value, _ = RegEnumValue(reghandle, i)
            except error:
                break
            i+=1            
            try:
                StateName = int(name, 16)
            except:
                continue

            if not DumpWnfData(StateName, value, ShowSd, ShowData):
                print("[Error] Something went wrong")
                return False
        if reghandle != None:
            RegCloseKey(reghandle)
    return True
        


###  Displays information on all temporary state names
def BruteForceWnfNames(DumpData):
    bruteName = WNF_STATE_NAME_INTERNAL()
    bruteName.value = 0
    bruteName.b.Version = 1
    bruteName.b.NameLifetime = WNF_STATE_NAME_LIFETIME['WnfTemporaryStateName'].value
    bruteName.b.PermanentData = 0

    for scope in WNF_DATA_SCOPE:
        bruteName.b.DataScope = scope.value 
        print("\n| WNF State Name [{:<7} Scope]                                  "
                    "| S | L | P | AC | N | CurSize | MaxSize | Changes |".format(WnfDataScopeStrings[scope.value]))
        print("-"*118)

        for i in range(0xFFFFFF):
            bruteName.b.Unique = i
            stateName = bruteName.value  ^ WNF_STATE_KEY
            #print(hex(stateName))
            exists = QueryWnfInfoClass(stateName, 'WnfInfoStateNameExist')
            if exists != 0:
                DumpWnfData(stateName, None, False, DumpData)


### Displays information on the given state name
def DumpKeyInfo(StateName, ShowSd, ShowData):
    reghandle = None
    internalName =  WNF_STATE_NAME_INTERNAL()
    internalName.value = int(StateName, 16) ^ WNF_STATE_KEY
    value = None
    if internalName.b.NameLifetime != WNF_STATE_NAME_LIFETIME['WnfTemporaryStateName'].value:
        try:
            reghandle = RegOpenKeyEx(HKEY_LOCAL_MACHINE,g_LifetimeKeyNames[internalName.b.NameLifetime], 0, KEY_READ)
        except Exception:
            print("[Error] Could not open root key: {}".format(g_LifetimeKeyNames[internalName.b.NameLifetime]))
            return False
      
        try:
            value, _ = RegQueryValueEx(reghandle, StateName)
        except error:
            print("[Error] Could not find the WnfName in the registry")
            return False
    print("\n| WNF State Name                                                  "
                "| S | L | P | AC | N | CurSize | MaxSize | Changes |")
    print("-"*118)
    DumpWnfData(int(StateName, 16), value, ShowSd, ShowData)         
    if reghandle != None:
        RegCloseKey(reghandle)
    return True   



### Reads the current data stored in the given state name
def DoRead(StateName):
    _, _, dataBuffer, bufferSize = ReadWnfData(int(StateName, 16))
    hexdump(dataBuffer.raw[0:bufferSize])


### Writes the given data into the given state name
def DoWrite(StateName, Data):
    StateName = ctypes.c_longlong(int(StateName, 16))
    dataBuffer = ctypes.c_char_p(Data)
    bufferSize = len(Data)
    status = ZwUpdateWnfStateData(ctypes.byref(StateName), dataBuffer, bufferSize, 0, 0, 0, 0)
    status = ctypes.c_ulong(status).value

    if status == 0:
        return True
    else:
        print('[Error] Could not write for this statename: 0x{:x}'.format(status))
        return False

   

#########################################################################################



############### MAIN ###############


if __name__ == "__main__":
    argParser = argparse.ArgumentParser(description="")
    readwritegroup = argParser.add_mutually_exclusive_group()
    dumpgroup = readwritegroup.add_argument_group()
    optiongroup = argParser.add_argument_group()
    dumpgroup = argParser.add_argument_group()
    
    dumpgroup.add_argument("-i","--info", action="store_true", help="Displays information on the given state name.")    
    dumpgroup.add_argument("-d","--dump", action="store_true", help="Displays information on all non-temporary state names. \
                                                                    \tUse -s to show the security descriptor for each name. \
                                                                    \tUse -v to dump the value of each name.")
    dumpgroup.add_argument("-b","--brut", action="store_true", help="Displays information on all temporary state names. \
                                                                    \t Can be combined with -d.\
                                                                    Use -v to dump the value of each name.")
    
    readwritegroup.add_argument("-r","--read", action="store_true", help="Reads the current data stored in the given state name.")
    readwritegroup.add_argument("-w","--write", action="store_true", help="Writes data into the given state name.")

    optiongroup.add_argument("-v", "--value", action="store_true", help="Dump the value of each name.")
    optiongroup.add_argument("-s", "--sid", action="store_true", help="Show the security descriptor for each name.")
    
    argParser.add_argument("WNF_NAME", nargs='?', type=str, help="state name")
    argParser.add_argument("dataFile", nargs='?', help="File name containing the data that will be written into the given state name.\n\
                                                                    \t This is a ugly hack to circumvent to encoding issue when passing a byte string to sys.argv.")
    
    args = argParser.parse_args()


    if args.info: # Displays information on the given state name
        if args.WNF_NAME != None:
            value = args.value | args.read
            DumpKeyInfo(
                FormatStateName(args.WNF_NAME), 
                args.sid, 
                value
            )
        else:
            sys.exit("[Error] No WNF_NAME provided.")
    elif args.dump or args.brut:
        if args.dump:  # Displays information on all non-temporary state names
            value = args.value | args.read    
            DumpWnfNames(args.sid, value)
    
        if args.brut: # Displays information on all temporary state names
            value = args.value | args.read    
            BruteForceWnfNames(value)

    else:
        if args.read : # Reads the current data stored in the given state name
            if args.WNF_NAME != None:
                DoRead(FormatStateName(args.WNF_NAME))
            else:
                sys.exit("[Error] No WNF_NAME provided.")
                
        elif args.write: # Writes the given data into the given state name
            if args.WNF_NAME != None and args.dataFile !=None:
                with open(args.dataFile, 'rb') as fl:
                    DoWrite(FormatStateName(args.WNF_NAME), fl.read())
            else:
                sys.exit("[Error] Need to provide WNF_NAME and data to write.")


    if not (args.info | args.read | args.write | args.dump | args.brut):
            sys.exit("[Error] Use -h to display some help.")
    
    

    



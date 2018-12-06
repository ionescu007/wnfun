"""

Copyright (c) 2018 Gabrielle Viala. All Rights Reserved.
https://blog.quarkslab.com/author/gwaby.html

"""

import ctypes
import argparse
import win32security
from enum import Enum
from hexdump import hexdump
import sys
from WellKnownWnfNames import g_WellKnownWnfNames # comment this if you don't have the file (you can generate it with )

ZwCreateWnfStateName = ctypes.windll.ntdll.ZwCreateWnfStateName
ZwUpdateWnfStateData = ctypes.windll.ntdll.ZwUpdateWnfStateData
ZwQueryWnfStateData = ctypes.windll.ntdll.ZwQueryWnfStateData
RtlSubscribeWnfStateChangeNotification = ctypes.windll.ntdll.RtlSubscribeWnfStateChangeNotification
RtlUnsubscribeWnfStateChangeNotification = ctypes.windll.ntdll.RtlUnsubscribeWnfStateChangeNotification
CreateEventA = ctypes.windll.kernel32.CreateEventA
WaitForSingleObject = ctypes.windll.kernel32.WaitForSingleObject
CloseHandle = ctypes.windll.kernel32.CloseHandle

GENERIC_ALL = 0x10000000
WNF_STATE_KEY = 0x41C64E6DA3BC0074


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
    _fields_ = [
        ("b", WNF_STATE_NAME_bits),
        ("value", ctypes.c_ulonglong)
    ]

class WNF_DATA_SCOPE(Enum):
    WnfDataScopeSystem, WnfDataScopeSession, WnfDataScopeUser, WnfDataScopeProcess, WnfDataScopeMachine = range(5)

class WNF_STATE_NAME_LIFETIME(Enum):
    WnfWellKnownStateName, WnfPermanentStateName, WnfPersistentStateName, WnfTemporaryStateName = range(4)

WnfLifetimeStrings = [
    "Well-Known",
    "Permanent",
    "Volatile",
    "Temporary"
    ]

WnfDataScopeStrings = [
    "System",
    "session",
    "User",
    "Process",
    "Machine"
    ]

class WnfCom(object):
    class NOTIFY_CONTEXT(ctypes.Structure):
        _fields_ = [
            ("NotifyEvent", ctypes.c_ulong),
            ("EventDestroyed", ctypes.c_bool)
        ]

    def __init__(self, WnfName = 0):
        # generic stuff
        self.StateName = ctypes.c_ulonglong(0)
        self.internalName = WNF_STATE_NAME_INTERNAL()
        self.verbose = True
        if WnfName != 0:
            self.SetStateName(WnfName)
        
        # callback for the listener
        self.callback_type = ctypes.CFUNCTYPE(
            ctypes.c_ulonglong, 
            ctypes.c_ulonglong, 
            ctypes.c_ulong, 
            ctypes.c_void_p, 
            ctypes.c_void_p, 
            ctypes.c_void_p, 
            ctypes.c_ulong)
        self.callback = self.callback_type(self.NotifyCallback)
  
        # security descriptor used for creating the server part
        everyoneSid = win32security.CreateWellKnownSid(1, None)
        acl = win32security.ACL()
        acl.AddAccessAllowedAce(win32security.ACL_REVISION, GENERIC_ALL, everyoneSid)
        pySd = win32security.SECURITY_DESCRIPTOR()
        pySd.SetSecurityDescriptorDacl(True, acl, False)
        self.rawSd = ctypes.create_string_buffer(memoryview(pySd).tobytes())


    def TooglePrint(self):
        self.verbose = not self.verbose

    def pprint(self, string):
        if self.verbose:
            print(string)

    def PrintInternalName(self):
        self.pprint("Encoded Name: {:x}, Clear Name: {:x}\n\t"
            "Version: {}, Permanent: {}, Scope: {}, Lifetime: {}, Unique: {}\n".format(
            self.StateName.value,
            self.internalName.value,
            self.internalName.b.Version,
            "Yes" if self.internalName.b.PermanentData else "No",
            WnfDataScopeStrings[self.internalName.b.DataScope],
            WnfLifetimeStrings[self.internalName.b.NameLifetime],
            self.internalName.b.Unique))


    def SetStateName(self, WnfName):
        tmpName = 0
        try:
            tmpName = g_WellKnownWnfNames[WnfName.upper()]
        except:
            if len(WnfName)>2 and WnfName[1] == 'x':
                WnfName = WnfName[2:]
            try:
                tmpName = int(WnfName, 16)
            except:
                tmpName = 0
                self.pprint("[Error] Could not validate the provided name")
                return False

        self.StateName = ctypes.c_longlong(tmpName)
        self.internalName.value = ctypes.c_ulonglong(tmpName ^ WNF_STATE_KEY)
        return True

    def CreateServer(self):
        status = ZwCreateWnfStateName(ctypes.byref(self.StateName),
                                        WNF_STATE_NAME_LIFETIME.WnfTemporaryStateName.value,
                                        WNF_DATA_SCOPE.WnfDataScopeMachine.value,
                                        False,
                                        0,
                                        0x1000,
                                        self.rawSd)
        if status != 0:
            self.pprint("[Error] Failed: {}".format(status))
            return 0

        self.pprint("[SERVER] StateName created: {:x}\n".format(self.StateName.value))
        self.internalName.value = ctypes.c_ulonglong(self.StateName.value ^ WNF_STATE_KEY)
        return self.StateName.value



    def Write(self, Data = b"Hello World"):
        if self.StateName.value == 0:
            self.pprint("[Error] Server not initialized. Use CreateServer() or SetStateName().")
            return 0
        if type(Data) != bytes:
            self.pprint("[Error] Could not read the data. Bytes string is expected.")
            return 0

        self.PrintInternalName()
        dataBuffer = ctypes.c_char_p(Data)
        bufferSize = len(Data)
        status = ZwUpdateWnfStateData(ctypes.byref(self.StateName), dataBuffer, bufferSize, 0, 0, 0, 0)
        status = ctypes.c_ulong(status).value
        
        if status != 0:
            self.pprint("[Error] Could not write: 0x{:x}\n\t Maybe the data is too big or you don't have write access?".format(status))
        else:
            self.pprint("State update: {} bytes written\n".format(bufferSize))        
        return status

    def Read(self):
        if self.StateName.value == 0:
            self.pprint("[Error] Client not initialized. Use SetStateName() to set a state name.")
            return False
        changeStamp = ctypes.c_ulong(0)
        dataBuffer = ctypes.create_string_buffer(4096)
        bufferSize = ctypes.c_ulong(ctypes.sizeof(dataBuffer))  
        res = ZwQueryWnfStateData(ctypes.byref(self.StateName), 
            0, 0, 
            ctypes.byref(changeStamp), 
            ctypes.byref(dataBuffer), 
            ctypes.byref(bufferSize)
        )
        bufferSize =  0 if res !=0 else bufferSize.value
        hexdump(dataBuffer.raw[0:bufferSize])

        return changeStamp.value, dataBuffer, bufferSize


    def Listen(self):
        if self.StateName.value == 0:
            self.pprint("[Error] Server not initialized. Use CreateServer() or SetStateName().")
            return False
        wnfSubscription = ctypes.c_void_p(0)
        notifyContext = self.NOTIFY_CONTEXT()
        notifyContext.EventDestroyed = False
        notifyContext.NotifyEvent = CreateEventA(0, 0, 0, 0)
        if(notifyContext.NotifyEvent == 0):
            self.pprint("[Error] Could not create event")
            return False
        
        self.pprint("[CLIENT]: Event registered: {}\n".format(notifyContext.NotifyEvent))

        res = RtlSubscribeWnfStateChangeNotification(
            ctypes.byref(wnfSubscription), 
            self.StateName, 
            0, 
            self.callback,
            ctypes.byref(notifyContext),
            0, 0, 0)

        if res != 0:
            self.pprint("[Error] WNF Sub Failed: {:x}".format(ctypes.c_ulong(res).value))
            CloseHandle(notifyContext.NotifyEvent)
            return False

        while not notifyContext.EventDestroyed:
            try:
                WaitForSingleObject(notifyContext.NotifyEvent, 1500)
            except KeyboardInterrupt:
                break

        self.pprint("[CLIENT]: Shutting down...")
        CloseHandle(notifyContext.NotifyEvent)
        RtlUnsubscribeWnfStateChangeNotification(wnfSubscription)
        return True
    
    def NotifyCallback (self, StateName, ChangeStamp, TypeId, CallbackContext, Buffer, BufferSize):
        notifyContext = ctypes.cast(CallbackContext, ctypes.POINTER(self.NOTIFY_CONTEXT))
        ArrayType = ctypes.c_char * BufferSize

        if Buffer == None and BufferSize == 0 and ChangeStamp == 0:
            self.pprint("[CLIENT]: NAME DESTROYED")
            notifyContext.contents.EventDestroyed = True
        
        else:    
            buff = ctypes.cast(Buffer, ctypes.POINTER(ArrayType)).contents[:BufferSize]
            self.pprint("[CLIENT] Timestamp: 0x{:x} Size: 0x{:x}\n Data:".format(
                ChangeStamp,
                BufferSize))
            
            output = b''.join(map(lambda x:x.to_bytes(1, byteorder='little'), buff))
            hexdump(output)

        return 0
    
############### MAIN ###############


if __name__ == "__main__":
    argParser = argparse.ArgumentParser(description="")
    argParser.add_argument("WNF_NAME", nargs='?', type=str, help="state name")
    args = argParser.parse_args()

    wnfserver = WnfCom()    
    if args.WNF_NAME:
        if not wnfserver.SetStateName(args.WNF_NAME):
            sys.exit("[Error] State name unknown.")
    else:
        wnfserver.CreateServer()
        wnfserver.Write()
    
    while True:
        try:
            Data = input(">")
        except KeyboardInterrupt as e:
            break
        wnfserver.Write(Data.encode())

    wnfserver.Read()
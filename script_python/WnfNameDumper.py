"""

Copyright (c) 2018 Gabrielle Viala. All Rights Reserved.
https://blog.quarkslab.com/author/gwaby.html

This script finds the wnf names table from a dll (typically perf_nt_c.dll) and dumps its content.
It's a pretty lazy script that searches for all the strings beginning by "WNF_" and xref them until finding the base of the table.

Usage:

$ python WnfNameDumper.py [-h] [-dump | -diff] [-v] [-o OUTPUT] file1 [file2]

Little script to dump or diff wnf name table from dll

positional arguments:
  file1
  file2

optional arguments:
  -h, --help            show this help message and exit
  -dump                 Dump the table into a file
  -diff                 Diff two tables and dump the discrepancies
  -v, --verbose         Print the description of the keys
  -o OUTPUT, --output OUTPUT
                        Output file (Default: output.txt)
  -py, --python         Change the output language to python (by default it's c)
  
Example:

    To dump the table into an output file:
        $ python3 WnfNameDumper.py -dump -o output.c perf_nt_c.dll
        
    To diff two dlls:
        $ python3 WnfNameDumper.py -diff -v -o output.txt perf_nt_c_15063.dll perf_nt_c_17713.dll


"""

import sys, os, struct
import lief 
import argparse

############### headers & footers printed in the output file

headerTable_py = "g_WellKnownWnfNames = {"
footerTable_py = "}"
formatLine_py = "\t\"{0}\": 0x{1}, {2}\n"
formatLastLine_py = "\t\"{0}\": 0x{1} {2}\n"
formatCmt_py = " \t# {}"

headerTable = """
typedef struct _WNF_NAME
{
    PCHAR Name;
    ULONG64 Value;
}WNF_NAME, *PWNF_NAME;

WNF_NAME g_WellKnownWnfNames[] =
{\n"""
footerTable = "};"
formatLine = "\t{{\"{0}\", 0x{1}}}, {2}\n"
formatLastLine = "\t{{\"{0}\", 0x{1}}} {2}\n"
formatCmt = " \t// {}"


headerAdded = """
################################################
#                   NEW KEYS                   #
################################################\n\n"""

headerDeleted = """\n\n
################################################
#                 DELETED KEYS                 #
################################################\n\n"""

headerModified = """\n\n
################################################
#                 MODIFIED KEYS                #
################################################\n\n"""


class dumbWnfParser(object):
    def __init__(self, binaryPath):
        self.binary = lief.parse(binaryPath)
        self.section = self.binary.get_section(".rdata")
        self.imgBase = self.binary.optional_header.imagebase
        self.ptr_size = 8 if self.binary.header.machine == lief.PE.MACHINE_TYPES.AMD64 else 4
        self.content = self.section.content
        self.sectionAddr = self.imgBase + self.section.virtual_address
        self.pattern = b'W\x00N\x00F\x00_\x00' # key pattern used to find th wnf table

        self.tableAddr = self.SearchForTable()


    # Small generator providing the addresses of strings containing the [pattern]
    def GetWnfOccurence(self, pattern):
        for occurence in self.section.search_all(pattern):
            yield(self.sectionAddr + occurence)


    # Xref each wnf key address and check if it's the first element of the wnf name table
    def SearchForTable(self):
        for address in self.GetWnfOccurence(self.pattern):
            offsetString = self.section.search_all(address)
            if offsetString != []:
                tableOff = offsetString[0]-self.ptr_size
                if self.VerifyTableAddr(tableOff) == True:
                    return tableOff
        return 0


    # Verifies that the wnf name table is at the provided offset ([tableOffset])
    def VerifyTableAddr(self, tableOffset):
        if tableOffset == 0:
            return 0
        currentOff = tableOffset    
        # At least test three entries in the table to remove false positives
        for _ in range(3): 
            # We should have a wnf value at the first offset
            valueAddr = self.GetPtr(currentOff)
            if struct.unpack('P', valueAddr)[0] == 0:
                return False
            value = self.GetContentFromVA(valueAddr, 8)
            if value == b'':
                return False

            # Just after, we should have a Wnf key
            currentOff+=self.ptr_size
            wnfkey = self.GetPtr(currentOff)
            if wnfkey == b'':
                return False
            value = self.GetContentFromVA(wnfkey, 8)
            if value != self.pattern:
                return False # This is not a valid key
            
            # At last, let's just check if we still have a pointer after that
            currentOff+=self.ptr_size
            desc = self.GetPtr(currentOff)
            if desc == b'':
                return False
            descAddr = struct.unpack('P', desc)[0]
            if descAddr < self.sectionAddr or descAddr >= (self.sectionAddr + self.section.size-self.ptr_size):
                return False

            currentOff+=self.ptr_size

        # Verifies that we are really at the beginning of the table
        currentOff=tableOffset-(self.ptr_size*2)
        wnfkey = self.GetPtr(currentOff)
        if struct.unpack('P', wnfkey)[0] != 0:
            value = self.GetContentFromVA(wnfkey, 8)
            if value == self.pattern: # we are not... 
                return False
        
        return True

    # Just reads [self.ptr_size] bytes of the section rdata at the provided [offset]
    def GetPtr(self, offset):
        assert(len(self.content) >= self.ptr_size+offset)
        return b''.join(map(lambda x:x.to_bytes(1, byteorder='little'), self.content[offset:offset+self.ptr_size]))


    # Extracts a unicode string from the section at the address [addr]
    def GetUnicodeStringFromVA(self, addr):
        startOffset = struct.unpack('P', addr)[0]-self.sectionAddr
        if(startOffset < 0) :
            return b''
        assert(self.content[startOffset] != 0)
        string = ""
        offset = startOffset
        while self.content[offset+2]!=0 :
            assert(self.content[offset+1]==0)
            offset+=2
        if startOffset < offset:
            string = b''.join(map(lambda x:x.to_bytes(1, byteorder='little'), self.content[startOffset:offset+2]))
        return string

   
    # Extracts [size] bytes from the section at the address [addr]
    def GetContentFromVA(self, addr, size):
        addr = struct.unpack('P', addr)[0]-self.sectionAddr
        if(addr < 0) :
            return b''
        return b''.join(map(lambda x:x.to_bytes(1, byteorder='little'), self.content[addr:addr+size]))
 

    # Parses the wnfNametable, populates a dictionary with the wnfNames and returns a dictionary containing all the entries found
    def DumpTable(self):
        wnfDico = {}
        assert(self.tableAddr != 0)
        currentOffset = self.tableAddr
        valAddr = self.GetPtr(currentOffset)
        while struct.unpack('P', valAddr)[0] != 0:

            value = struct.unpack('Q', self.GetContentFromVA(valAddr, 8))[0]
            
            currentOffset += self.ptr_size
            keyAddr = self.GetPtr(currentOffset)
            if struct.unpack('P', keyAddr)[0] == 0:
                raise Exception('Cannot get the address of the key. Check the base address of the wnfName table')
            key = self.GetUnicodeStringFromVA(keyAddr).decode('utf-16')
        
            currentOffset += self.ptr_size
            descAddr = self.GetPtr(currentOffset)
            if struct.unpack('P', descAddr)[0] == 0:
                raise Exception('Cannot get the address of the description. Check the base address of the wnfName table')
            desc = self.GetUnicodeStringFromVA(descAddr).decode('utf-16')       

            wnfDico[key] = (value, desc)
            currentOffset += self.ptr_size
            valAddr = self.GetPtr(currentOffset)
        return wnfDico


############### Pretty print and output stuff ############### 

# diff two wnf dictionnaries and outputs the discrepancies as 3 differents dictionnaries
def DiffDico(dicoOld, dicoNew):
    addedKey = {key: dicoNew[key] for key in set(dicoNew)-set(dicoOld)}
    removedKey = {key: dicoOld[key] for key in set(dicoOld)-set(dicoNew)}
    modifiedValue ={key: (dicoOld[key], dicoNew[key]) for key in set(dicoOld) & set(dicoNew) if dicoOld[key] != dicoNew[key]}
    return addedKey, removedKey, modifiedValue
    

# simply opens a file and writes the content of the wnfName dictionnary in it
def WriteTableInFile(dico, fileName,append = False, verbose = False):
    fileaccess = 'a' if append else 'w'
    with open(fileName, fileaccess) as outfile:
        outfile.write(headerTable)
        sortedDico = sorted(dico)
        for key in sortedDico[:-1]:
            value, desc = dico[key]
            if verbose == True:
                desc = formatCmt.format(desc)
            else:
                desc = ""
            line = formatLine.format(key, format(value, '08x'), desc)
            outfile.write(line)

        value, desc = dico[sortedDico[-1]]
        if verbose == True:
            desc = formatCmt.format(desc)
        else:
            desc = ""   
        line = formatLastLine.format(sortedDico[-1], format(value, '08x'), desc)
        outfile.write(line)
        outfile.write(footerTable)

# Just pretty prints the dictionnary generated by the diff
def PrettyPrintDiff(addedDico, removedDico, modifDico, fileName, verbose = False):
    if addedDico != {}:
        with open(fileName, "w") as outfile:
            outfile.write(headerAdded)
        WriteTableInFile(addedDico, fileName, True, verbose)

    if removedDico != {}:
        with open(fileName, "a") as outfile:
            outfile.write(headerDeleted)
        WriteTableInFile(removedDico, fileName, True, verbose)
    
    if modifDico != {}:
        with open(fileName, "a") as outfile:
            outfile.write(headerModified)
            for key in modifDico:
                old, new = modifDico[key] # (value, desc)
                line = "Key {0}: {1} -> {2} \n {3} \n->\n {4}\n\n--\n\n".format(key, format(old[0], '08x'), format(new[0], '08x'), old[1], new[1])
                outfile.write(line)
   

############### MAIN ###############


if __name__ == "__main__":
    argParser = argparse.ArgumentParser(description="Little script to dump or diff wnf name table from dll")
    group = argParser.add_mutually_exclusive_group()
    group.add_argument("-dump", action="store_true", help="Dump the table into a file")
    group.add_argument("-diff", action="store_true", help="Diff two tables and dump the discrepancies")
    argParser.add_argument("-v", "--verbose", action="store_true", help="Print the description of the keys")
    argParser.add_argument("-o", "--output", type=str, help="Output file (Default: output.txt)", default="output.txt")
    argParser.add_argument("-py", "--python",action="store_true", help="Change the output language to python (by default it's c)")
    argParser.add_argument("file1", type=str)
    argParser.add_argument("file2", nargs='?', type=str, default="")
    args = argParser.parse_args()

    if args.python:
        headerTable = headerTable_py
        footerTable = footerTable_py
        formatLine = formatLine_py
        formatLastLine = formatLastLine_py
        formatCmt = formatCmt_py

    try:
        dumper1 = dumbWnfParser(args.file1)
    except Exception as e:
        sys.exit("[Error] Error with file {0} : {1}.".format(args.file1, e))

    if dumper1.tableAddr == 0:
        sys.exit("[Error] Could not find the WNF name table in {}.".format(args.file1))


    ####### diffing 
    if args.diff:
        if args.file2 == "":
            sys.exit("usage: {} -diff oldDllName newDllName".format(os.path.basename(__file__)))

        # same stuff for the second file
        try:
            dumper2 = dumbWnfParser(args.file2)
        except Exception as e:
            sys.exit("[Error] Error with file {0} : {1}...".format(args.file2, e))
        
        if dumper2.tableAddr == 0:
            sys.exit("[Error] Could not find the WNF name table in {}.".format(args.file2))

        # diffing
        try:
            dicoOld = dumper1.DumpTable()
            dicoNew = dumper2.DumpTable()
            added, deleted, modified = DiffDico(dicoOld, dicoNew)
        except Exception as e:
            sys.exit("[Error] {}".format(e))

        # writing everithing
        try:
            PrettyPrintDiff(added, deleted, modified, args.output, args.verbose)
        except Exception as e:
            sys.exit("[Error] {}".format(e))
    
    
    ###### dumping
    else:

        try:
            WriteTableInFile(dumper1.DumpTable(), args.output, False, args.verbose)
        except Exception as e:
            sys.exit("[Error] {}".format(e))

# Learning-PEfile-package
```Python
import pefile
pe = pefile.PE("C:\Windows\System32\kernel32.dll")

"Gives the info about dos header"
DosHeader = pe.DOS_HEADER
print(DosHeader)


NtHeader = pe.NT_HEADERS
print(NtHeader)

FileHeader = pe.NT_HEADERS.FILE_HEADER
print(FileHeader)


OptionalHeader = pe.NT_HEADERS.OPTIONAL_HEADER
print(OptionalHeader)


DataDirectory = pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY
print(DataDirectory)

print("Printing out virtual address and size of each directory\n")

pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size

print("Listing export and import symbols\n")


print("Export\n")
exportNameList = []
exportDirectory = pe.DIRECTORY_ENTRY_EXPORT
exportDirectory.symbols 
for function in exportDirectory.symbols:
     print(hex(pe.OPTIONAL_HEADER.ImageBase + function.address), function.name.decode('utf-8'))
     exportNameList.append(function.name.decode('utf-8'))


print("Imports\n")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print('\t' + entry.dll.decode('utf-8'))
    dll_name = entry.dll.decode('utf-8')
    if dll_name == "KERNEL32.dll":
        print("[*] Kernel32.dll imports:")
        for func in entry.imports:
            print("\t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))


print("Listing sections\n")
for section in pe.sections:
    print(section.Name.decode('utf-8'))
    print("\tVirtual Address: " + hex(section.VirtualAddress))
    print("\tVirtual Size: " + hex(section.Misc_VirtualSize))
    print("\tRaw Size: " + hex(section.SizeOfRawData))
```






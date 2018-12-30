#!/usr/bin/python 2.7

import os
import re
import sys

def verified_app_path(path):
    #distinguish Big-Endian and Little-Endian 
    global binary_file_arch
    if path.endswith(".app"):
        appname = path.split('/')[-1].split('.')[0]
        path = os.path.join(path,appname)
    if not os.path.isfile(path):
        return None
    file_detail = os.popen('file -b ' + path).read()
    if not file_detail.startswith('Mach-O'):
        return None    
    binary_file_arch = file_detail.split(' ')[-1].strip()

    return path

def pointers_from_binary(line):
    if len(line) < 16:
        return None
    line = line[16:].strip().split(' ')
    pointers = set()
    if binary_file_arch == 'x86_64':
        #line example:00000001030cec80	d8 75 15 03 01 00 00 00 68 77 15 03 01 00 00 00
        if len(line) != 16:
            return None
        pointers.add(''.join(reversed(line[4:8])).join(reversed(line[0:4]))[7:])
        pointers.add(''.join(reversed(line[12:16])).join(reversed(line[8:12]))[7:])
        return pointers
    if binary_file_arch == 'arm64':
        #line example:00000001030bcd20	03138580 00000001 03138878 00000001
        if len(line) != 4:
            return None
        pointers.add((line[1]+line[0])[7:])
        pointers.add((line[3]+line[2])[7:])
        return pointers

    return None

def class_ref_pointers(path):
    print 'Get class ref pointers...'
    ref_pointers = set()
    lines = os.popen("/usr/bin/otool -v -s __DATA __objc_classrefs %s" % path).readlines()
    for line in lines:
        pointers = pointers_from_binary(line)
        if not pointers:
            continue
        ref_pointers = ref_pointers.union(pointers)
    if len(ref_pointers) == 0:
        exit('Error:class ref pointers null')
    return ref_pointers
    
def class_list_pointers(path):
    print 'Get class list pointers...'
    list_pointers = set()
    lines = os.popen("/usr/bin/otool -v -s __DATA __objc_classlist %s" % path).readlines()
    for line in lines:
        pointers = pointers_from_binary(line)
        if not pointers:
            continue
        list_pointers = list_pointers.union(pointers)
    if len(list_pointers) == 0:
        exit('Error:class list pointers null')
    return list_pointers

def class_symbles(path):
    print 'Get class symbles...'
    symbles = {}
    re_class_name = re.compile("\w{7}(\w{9}) .* _OBJC_CLASS_\$_(.+)")
    lines = os.popen("nm -nm %s" % path).readlines()
    for line in lines:
        result = re_class_name.findall(line)
        if result:
            (address,symble) = result[0]
            if not symble.startswith('TT') or symble.startswith('TTL'):
                continue
            symbles[address] = symble
    if len(symbles) == 0:
        exit('Error:class symbles null')
    return symbles

def class_unref_symbles(path):
    list_pointers = class_list_pointers(path)
    ref_pointers = class_ref_pointers(path)

    unref_pointers = set()
    for class_pointer in list_pointers:
        if class_pointer not in ref_pointers:
            unref_pointers.add(class_pointer)

    symbles = class_symbles(path)
    unref_symbles = set() 
    for unref_pointer in unref_pointers:
        if unref_pointer in symbles:
            unref_symbles.add(symbles[unref_pointer])

    return unref_symbles

if __name__ == "__main__":
    path = raw_input('Please input app path\nFor example:/Users/xxx/Library/Developer/Xcode/DerivedData/***/Build/Products/Dev-iphoneos/***.app\n') 
    path = verified_app_path(path)
    if not path:
        sys.exit('Error:Invalid app path')

    unref_symbles = class_unref_symbles(path)
    script_path = sys.path[0].strip()

    f = open(script_path+"/result.txt","w")
    f.write( "unref class number:   %d\n" % len(unref_symbles))
    f.write("\n")
    for unref_symble in unref_symbles:
        f.write(unref_symble+"\n")
    f.close()

    print 'Done! result.txt already stored in scrpit dir.'

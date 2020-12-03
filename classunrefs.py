#!/usr/bin/python3

import os
import re
import sys

def verified_app_path(path):
    if path.endswith('.app'):
        # appname = path.split('/')[-1].split('.')[0]
        appname = os.path.splitext(path)[0].split('/')[-1]
        path = os.path.join(path, appname)
    if not os.path.isfile(path):
        return None
    if not os.popen('file -b ' + path).read().startswith('Mach-O'):
        return None
    return path


def pointers_from_binary(line, binary_file_arch):
    if len(line) < 16:
        return None
    line = line[16:].strip().split(' ')
    pointers = set()
    if binary_file_arch == 'x86_64':
        #untreated line example:00000001030cec80	d8 75 15 03 01 00 00 00 68 77 15 03 01 00 00 00
        if len(line) >= 8:
            pointers.add(''.join(line[4:8][::-1] + line[0:4][::-1]))
        if len(line) >= 16:
            pointers.add(''.join(line[12:16][::-1] + line[8:12][::-1]))
        return pointers
    #arm64 confirmed,armv7 arm7s unconfirmed
    if binary_file_arch.startswith('arm'):
        #untreated line example:00000001030bcd20	03138580 00000001 03138878 00000001
        if len(line) >= 2:
            pointers.add(line[1] + line[0])
        if len(line) >= 4:
            pointers.add(line[3] + line[2])
        return pointers
    return None


def class_ref_pointers(path, binary_file_arch):
    print('Get class ref pointers...')
    ref_pointers = set()
    lines = os.popen('/usr/bin/otool -v -s __DATA __objc_classrefs %s' % path).readlines()
    for line in lines:
        pointers = pointers_from_binary(line, binary_file_arch)
        if not pointers:
            continue
        ref_pointers = ref_pointers.union(pointers)
    if len(ref_pointers) == 0:
        exit('Error:class ref pointers null')
    return ref_pointers


def class_list_pointers(path, binary_file_arch):
    print('Get class list pointers...')
    list_pointers = set()
    lines = os.popen('/usr/bin/otool -v -s __DATA __objc_classlist %s' % path).readlines()
    for line in lines:
        pointers = pointers_from_binary(line, binary_file_arch)
        if not pointers:
            continue
        list_pointers = list_pointers.union(pointers)
    if len(list_pointers) == 0:
        exit('Error:class list pointers null')
    return list_pointers


def class_symbols(path):
    print('Get class symbols...')
    symbols = {}
    #class symbol format from nm: 0000000103113f68 (__DATA,__objc_data) external _OBJC_CLASS_$_TTEpisodeStatusDetailItemView
    re_class_name = re.compile('(\w{16}) .* _OBJC_CLASS_\$_(.+)')
    lines = os.popen('nm -nm %s' % path).readlines()
    for line in lines:
        result = re_class_name.findall(line)
        if result:
            (address, symbol) = result[0]
            symbols[address] = symbol
    if len(symbols) == 0:
        exit('Error:class symbols null')
    return symbols

def filter_super_class(unref_symbols):
    re_subclass_name = re.compile("\w{16} 0x\w{9} _OBJC_CLASS_\$_(.+)")
    re_superclass_name = re.compile("\s*superclass 0x\w{9} _OBJC_CLASS_\$_(.+)")
    #subclass example: 0000000102bd8070 0x103113f68 _OBJC_CLASS_$_TTEpisodeStatusDetailItemView
    #superclass example: superclass 0x10313bb80 _OBJC_CLASS_$_TTBaseControl
    lines = os.popen("/usr/bin/otool -oV %s" % path).readlines()
    subclass_name = ""
    superclass_name = ""
    for line in lines:
        subclass_match_result = re_subclass_name.findall(line)
        if subclass_match_result:
            subclass_name = subclass_match_result[0]
        superclass_match_result = re_superclass_name.findall(line)
        if superclass_match_result:
            superclass_name = superclass_match_result[0]

        if len(subclass_name) > 0 and len(superclass_name) > 0:
            if superclass_name in unref_symbols and subclass_name not in unref_symbols:
                unref_symbols.remove(superclass_name)
            superclass_name = ""
            subclass_name = ""
    return unref_symbols

def class_unref_symbols(path,reserved_prefix,filter_prefix):
    #binary_file_arch: distinguish Big-Endian and Little-Endian
    #file -b output example: Mach-O 64-bit executable arm64
    binary_file_arch = os.popen('file -b ' + path).read().split(' ')[-1].strip()
    unref_pointers = class_list_pointers(path, binary_file_arch) - class_ref_pointers(path, binary_file_arch)
    if len(unref_pointers) == 0:
        exit('Finish:class unref null')

    symbols = class_symbols(path)
    unref_symbols = set()
    for unref_pointer in unref_pointers:
        if unref_pointer in symbols:
            unref_symbol = symbols[unref_pointer]
            if len(reserved_prefix) > 0 and not unref_symbol.startswith(reserved_prefix):
                continue
            if len(filter_prefix) > 0 and unref_symbol.startswith(filter_prefix):
                continue
            unref_symbols.add(unref_symbol)
    if len(unref_symbols) == 0:
        exit('Finish:class unref null')
    return filter_super_class(unref_symbols)


if __name__ == '__main__':
    path = input('Please input app path\nFor example:/Users/yuencong/Library/Developer/Xcode/DerivedData/***/Build/Products/Dev-iphoneos/***.app\n').strip()
    path = verified_app_path(path)
    if not path:
        sys.exit('Error:invalid app path')

    reserved_prefix = ''
    filter_prefix = ''
    unref_symbols = class_unref_symbols(path, reserved_prefix, filter_prefix)
    script_path = sys.path[0].strip()

    f = open(script_path + '/result.txt','w')
    f.write('classunrefs count: %d\n' % len(unref_symbols))
    f.write('Precondition: reserve class startwiths \'%s\', filter class startwiths \'%s\'.\n\n' %(reserved_prefix, filter_prefix))
    for unref_symbol in unref_symbols:
        print('classunref: ' + unref_symbol)
        f.write(unref_symbol + "\n")
    f.close()

    print('Done! result.txt already stored in script dir.')

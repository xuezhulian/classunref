# classunref
查找OC中未使用的类

执行 python3 classunrefs.py

输入的第一个参数为xxx.app，可以把Xcode products目录下的xxx.app拖到命令行，这个参数是为了拿到.app下的mach-o文件，分析使用的类和未使用的类。


from randomness import *

def change_metadata() :
    f = open("DllExecutor.rc", "r")
    f_c = f.readlines()
    f.close()
 
    o = open("DllExecutor.rc", "w")
    for line in f_c :
        if "CompanyName" in line :
            line = f'\t\t\tVALUE "CompanyName", "Microsoft"\n'
         
        elif "FileDescription" in line :
            line = f'\t\t\tVALUE "FileDescription", "{GetRandomString(20)}"\n'
        
        elif "InternalName" in line :
            line = f'\t\t\tVALUE "InternalName", "{GetRandomString(7)}.exe"\n'
        
        elif "OriginalFilename" in line :
            line = f'\t\t\tVALUE "OriginalFilename", "{GetRandomString(7)}.exe"\n'
        
        elif "ProductName" in line :
            line = f'\t\t\tVALUE "ProductName", "{GetRandomString(7)}.exe"\n'
        
        o.write(line)
        
    o.close()
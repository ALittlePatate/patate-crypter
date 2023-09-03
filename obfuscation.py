import os, string, re

"""
Creates :
    - Random variables (local and globals)
    - Random operations on globals
"""

def GetRandomBool() :
    result = os.urandom(3)
    r= sum(result) < 381.04
    return r #average

def GetRandomNumber() :
    result = os.urandom(4)
    return int(sum(result))

def GetRandomRange(a, b):
    if a > b:
        a, b = b, a  # Swap a and b if a is greater than b

    range_size = b - a + 1  # Calculate the size of the range

    # Calculate the number of bits required to represent all values in the range
    num_bits = 0
    while 2 ** num_bits < range_size:
        num_bits += 1

    # Generate a random number in binary representation using GetRandomBool()
    random_binary = [GetRandomBool() for _ in range(num_bits)]

    # Convert the binary representation to an integer within the specified range
    random_integer = 0
    for i, bit in enumerate(random_binary):
        random_integer += bit * (2 ** i)

    # Map the generated integer to the desired range [a, b]
    mapped_value = a + random_integer
    if mapped_value > b : return GetRandomRange(a, b)
    
    return mapped_value

def GetRandomString(l) :
    letters = string.ascii_lowercase
    s = ""
    while len(s) < l :
        r = GetRandomRange(0, len(letters)-1)
        s += letters[r]

    return s

types = ["short", "unsigned short", "int", "unsigned int", "long", "unsigned long", "float", "double"]
operations = ["-", "+", "^", "*", "/"]
global_vars = {}
functions = []
in_func = False

def GetRandomVar() :
    global global_vars
    global in_func
    vtype = types[GetRandomRange(0, len(types)-1)]
    vname = GetRandomString(10)
    t = vtype + " " + vname + " = "
    
    val = str(GetRandomNumber())
    if vtype == "float" or vtype == "double" : val = str(GetRandomNumber())+"."+str(GetRandomNumber())
    if vtype == "float" : val += "f"
    res = t + val + ";"
    
    if not in_func :
        global_vars[vname] = vtype
        
    return res

def GetRandomOperation() :
    global global_vars
    vars_ = list(global_vars.items())
    if len(vars_) < 1 : return ""

    v1 = vars_[GetRandomRange(0, len(vars_)-1)]
    
    op = operations[GetRandomRange(0, len(operations)-1)]
    res = ""
    res += v1[0] + " " + op + "= "
    
    vtype = v1[1]
    val = str(GetRandomNumber())
    if vtype == "float" or vtype == "double" :
        if op == "^" : return GetRandomOperation()
        val = str(GetRandomNumber())+"."+str(GetRandomNumber())
    if vtype == "float" : val += "f"
    
    res += val + ";"
    return res

def GetRandomFunction() :
    global functions
    name = GetRandomString(6)
    functions.append(name)
    
    body = "int "+name+"(const char* a1) {\n"
    body += f"\tint bb = {GetRandomNumber()};\n"
    body += "\tfor (int i = 0; i < 10; i++) {\n\t\tCreateMutexA(NULL, false, a1);\n\t\tbb++;\n\t}\n\treturn bb;\n}"
        
    return body

def CallRandomFunction() :
    global functions
    if len(functions) < 1 : return ""
    
    sub = functions[GetRandomRange(0, len(functions)-1)]
    return "int " + GetRandomString(6) + " = " + sub + "(\""+GetRandomString(5)+"\");"

def obfuscate(PASS) :
    global global_vars
    global functions
    global in_func
    dont = ["for", "if", "else", "while"]
    func_def_pattern = r'\b\w+\s+\w+\s*\([^)]*\)\s*'
    
    f = open("DO_NOT_TOUCH.cpp", "r")
    o = open("main.cpp", "w")

    lines = f.readlines()
    for k in range(PASS) :
        in_comment = False
        in_switch = False
        in_asm = False
        in_func_delay = False
        global_vars = {}
        functions = []
        out = []
        for line in lines :
            out.append(line)
            
            if in_func_delay and "}" in line :
                in_func = False
                in_func_delay = False
            elif in_func_delay : continue
                
            if "//START" in line : in_func = True
            if "/*" in line : in_comment = True
            elif "*/" in line : in_comment = False
            if "switch" in line : in_switch = True
            elif in_switch and "}" in line : in_switch = False
            if "__asm" in line : in_asm = True
            elif in_asm and "}" in line : in_asm = False
            skip = False
            for w in dont : 
                if w in line : skip = True
            if skip : continue
            
            a = "{" in line or "}" in line or "#" in line
            b = re.search(func_def_pattern, line) != None
            
            if b or a or in_comment or in_switch or in_asm : continue # we can't write
            
            if GetRandomBool() : # do we create a variable ?
                out.append(GetRandomVar()+"\n")
                
            if GetRandomBool() and in_func : # do we do an operation on globals ?
                out.append(GetRandomOperation()+"\n")
            
            if GetRandomBool() and not in_func : # do we create a function ?
                out.append(GetRandomFunction()+"\n")
            
            if GetRandomBool() and in_func : # do we call a function ?
                out.append(CallRandomFunction()+"\n")

            if "//END" in line : in_func_delay = True

        lines = out
    
    o.writelines(out)
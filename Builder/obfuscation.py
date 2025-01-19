import os, string, re
from randomness import *

"""
Creates :
    - Random variables (local and globals)
    - Random operations on globals
    - Random function definitions
    - Random function calls
    - Random control flow
"""

types = ["short", "unsigned short", "int", "unsigned int", "long", "unsigned long"] #"float", "double"]
operations = ["-", "+", "^", "*", "/"]
global_vars = {}
functions = []
in_func = False

def GetRandomVar() :
    global global_vars
    global in_func
    vtype = types[GetRandomRange(0, len(types)-1)]
    vname = GetRandomString(15)
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
    name = GetRandomString(15)
    functions.append(name)
    
    body = "int "+name+"(const char* a1) {\n"
    body += "\tif (a1 <= (void*)0x00100000) return 0;\n"
    body += "\tchar aaa = ((char)((int)'0' + 1));\n"
    body += f"\tint bb = {GetRandomNumber()};\n"
    body += f"\tint r = {GetRandomNumber()};\n"
    body += "\tfor (int i = 0; i < bb; i++) {\n\t\tr ^= i;\n\t}\n\treturn bb;\n}"
        
    return body

def CallRandomFunction() :
    global functions
    if len(functions) < 1 : return ""
    
    sub = functions[GetRandomRange(0, len(functions)-1)]
    return "int " + GetRandomString(15) + " = " + sub + "(\""+GetRandomString(10)+"\");"

def GetAsmBlock(branch1, branch2, var, end, sub) :
    asm_block = """\n\t\tcmp eax, """+str(GetRandomNumber())+"""
		jne """+branch1+"""
		jmp """+branch2+"""
	"""+branch1+""":"""
    
    
    if GetRandomRange(0, 4) > 1 :
        branch1 = GetRandomString(20)
        branch2_ = GetRandomString(20)
        asm_block += GetAsmBlock(branch1, branch2_, var, end, sub)
        
    asm_block += "\n\t"+branch2+":\n\t\tmov eax, "+var+"\n\t\tcall "+sub

    return asm_block

def GetRandomAssemblyBlock() :
    global functions
    if len(functions) < 1 : return ""
    sub = functions[GetRandomRange(0, len(functions)-1)]

    branch1 = GetRandomString(20)
    branch2 = GetRandomString(20)
    end = GetRandomString(20)
    var = GetRandomString(15)

    r = """const char* """+var+""" = \""""+GetRandomString(5)+"""\";\n__asm {"""
    
    for i in range(GetRandomRange(0, 30)) :
        branch1 = GetRandomString(20)
        branch2 = GetRandomString(20)
        end = GetRandomString(20)
        r += GetAsmBlock(branch1, branch2, var, end, sub)
    
    r += """\n};"""
    return r

def generate_switch_statement(variable_name, exit_value, depth=0):
    indent = "    " * depth
    switch_code = f"{indent}switch ({variable_name}) {{\n"

    num_cases = GetRandomRange(2, 5)
    for _ in range(num_cases):
        case_value = GetRandomRange(1, 10**6)
        switch_code += f"{indent}  case {case_value}:\n"
        if depth < 2 and GetRandomRange(0, 4) > 1 :
            switch_code += generate_switch_statement(variable_name, exit_value, depth + 1)
        else:
            switch_code += f"{indent}    {{\n"
            switch_code += f"{indent}        // Your code here\n"
            switch_code += f"{indent}        break;\n"
            switch_code += f"{indent}    }}\n"

    switch_code += f"{indent}  default:\n"
    switch_code += f"{indent}    {{\n"
    switch_code += f"{indent}        {variable_name} = {exit_value};\n"
    switch_code += f"{indent}        break;\n"
    switch_code += f"{indent}    }}\n"

    switch_code += f"{indent}}}\n"

    return switch_code

def GetRandomControlFlow():
    cpp_code = ""
    var_name = GetRandomString(15)
    end_num = GetRandomNumber()
    cpp_code += f"int {var_name} = {end_num};\n"
    cpp_code += "while ("+var_name+" != "+str(end_num)+") {\n"
    cpp_code += generate_switch_statement(var_name, end_num)
    cpp_code += "    }\n"

    return cpp_code

FILES_TO_OBFUSCATE = {"../Crypter/main.cpp":"../Crypter/DO_NOT_TOUCH.cpp"}# "getapi.cpp":"DO_NOT_TOUCH_API.cpp"}
def obfuscate(PASS, CFLOW_PASS, cflow, junk, is64bit) :
    if PASS < CFLOW_PASS : PASS = CFLOW_PASS
    
    if not cflow and not junk : PASS = 0
    
    global global_vars
    global functions
    global in_func
    func_def_pattern = r'\b\w+\s+\w+\s*\([^)]*\)\s*'
    
    for outfile, infile in FILES_TO_OBFUSCATE.items():
        if PASS == 0 : break;
        
        f = open(infile, "r")
        o = open(outfile, "w")
        out = []

        lines = f.readlines()
        for k in range(PASS) :
            in_comment = False
            in_switch = False
            in_asm = False
            in_dowhile = False
            in_struct = False
            can_code = False
            wait_for_func_close = False
            in_debug = False
            global_vars = {}
            functions = []
            out = []
            idx = 0
            for line in lines :
                idx += 1
                out.append(line)
                
                if idx+1 < len(lines)-1 and "//END" in lines[idx+1] or "//END" in line:
                    in_func = False
                    wait_for_func_close = True
                    continue
                if wait_for_func_close and "}" in line :
                    in_func = False
                    wait_for_func_close = False
                    continue
                if wait_for_func_close :
                    continue
                
                if "//START" in line : in_func = True
                if "/*" in line : in_comment = True
                elif "*/" in line : in_comment = False
                if "switch" in line : in_switch = True
                elif in_switch and "}" in line and not "case" in line and not "default" in line : in_switch = False
                if "__asm" in line : in_asm = True
                elif in_asm and "}" in line : in_asm = False
                if "struct" in line : in_struct = True
                elif in_struct and "}" in line : in_struct = False
                if "// Your code here" in line :
                    #can_code = True
                    pass
                elif "break;" in line and can_code :
                    can_code = False
                if "#ifdef _DEBUG" in line :
                    in_debug = True
                elif in_debug and "#endif" in line :
                    in_debug = False
                    continue
                if "do {" in line :
                    in_dowhile = True
                elif in_dowhile and "while" in line :
                    in_dowhile = False
                    continue
                
                if in_debug : continue
                if in_dowhile : continue
                a = "{" in line or "}" in line or "#" in line
                b = re.search(func_def_pattern, line) != None
                
                if not can_code :
                    if b or a or in_comment or in_switch or in_asm or in_struct : continue # we can't write

                if GetRandomBool() and junk and k < PASS : # do we create a variable ?
                    out.append(GetRandomVar()+"\n")

                if GetRandomBool() and in_func and junk  and k < PASS : # do we do an operation on globals ?
                    out.append(GetRandomOperation()+"\n")
                    
                if GetRandomBool() and not in_func : # do we create a function ?
                    out.append(GetRandomFunction()+"\n")
                
                if GetRandomBool() and in_func : # do we call a function ?
                    out.append(CallRandomFunction()+"\n")
                
                if GetRandomBool() and in_func and cflow and k < CFLOW_PASS and not is64bit : # do we mess up control flow ?
                    out.append(GetRandomAssemblyBlock()+"\n")
                
                if GetRandomBool() and in_func and cflow and k < CFLOW_PASS : # do we mess up control flow ?
                    out.append(GetRandomControlFlow()+"\n")

            lines = out
        
        fake_api = """#define k_AreFileApisANSI (*(DWORD(WINAPI *)(VOID)) AreFileApisANSI)\r\n
    #define k_AssignProcessToJobObject (*(DWORD(WINAPI *)(DWORD,DWORD)) AssignProcessToJobObject)\r\n
    #define k_CancelWaitableTimer (*(DWORD(WINAPI *)(DWORD)) CancelWaitableTimer)\r\n
    #define k_ClearCommBreak (*(DWORD(WINAPI *)(DWORD)) ClearCommBreak)\r\n
    #define k_ClearCommError (*(DWORD(WINAPI *)(DWORD,DWORD,DWORD)) ClearCommError)\r\n
    #define k_ConvertFiberToThread (*(DWORD(WINAPI *)(VOID)) ConvertFiberToThread)\r\n
    #define k_ConvertThreadToFiber (*(DWORD(WINAPI *)(DWORD)) ConvertThreadToFiber)\r\n
    #define k_CreateFiber (*(DWORD(WINAPI *)(DWORD,DWORD,DWORD)) CreateFiber)\r\n
    #define k_CreateFiberEx (*(DWORD(WINAPI *)(DWORD,DWORD,DWORD,DWORD,DWORD)) CreateFiberEx)\r\n
    #define k_CreateIoCompletionPort (*(DWORD(WINAPI *)(DWORD,DWORD,DWORD,DWORD)) CreateIoCompletionPort)\r\n"""
        
        static_imports = """DWORD USER3221_Array[] = { (DWORD)GetWindowLongA, (DWORD)wvsprintfA, (DWORD)SetWindowPos, (DWORD)FindWindowA,\r\n
    (DWORD)RedrawWindow, (DWORD)GetWindowTextA, (DWORD)EnableWindow, (DWORD)GetSystemMetrics,\r\n
    (DWORD)IsWindow, (DWORD)CheckRadioButton, (DWORD)UnregisterClassA, (DWORD)SetCursor,\r\n
    (DWORD)GetSysColorBrush, (DWORD)DialogBoxParamA, (DWORD)DestroyAcceleratorTable, (DWORD)DispatchMessageA,\r\n
    (DWORD)TranslateMessage, (DWORD)LoadIconA, (DWORD)EmptyClipboard, (DWORD)SetClipboardData, (DWORD)SetFocus,\r\n
    (DWORD)CharUpperA, (DWORD)OpenClipboard, (DWORD)IsDialogMessageA, (DWORD)TranslateAcceleratorA, (DWORD)GetMessageA,\r\n
    (DWORD)LoadAcceleratorsA, (DWORD)RemoveMenu, (DWORD)InvalidateRect, (DWORD)ChildWindowFromPoint, (DWORD)PostMessageA,\r\n
    (DWORD)DestroyCursor, (DWORD)CreateDialogParamA, (DWORD)GetWindowRect, (DWORD)IsMenu, (DWORD)GetSubMenu, (DWORD)SetDlgItemInt,\r\n
    (DWORD)GetWindowPlacement, (DWORD)CharLowerBuffA, (DWORD)EnableMenuItem, (DWORD)CheckMenuRadioItem, (DWORD)GetSysColor,\r\n
    (DWORD)KillTimer, (DWORD)DestroyIcon, (DWORD)DestroyWindow, (DWORD)PostQuitMessage, (DWORD)GetClientRect, (DWORD)MoveWindow,\r\n
    (DWORD)GetSystemMenu, (DWORD)SetTimer, (DWORD)SetWindowPlacement, (DWORD)InsertMenuItemA, (DWORD)GetMenu, (DWORD)CheckMenuItem,\r\n
    (DWORD)SetMenuItemInfoA, (DWORD)SetActiveWindow, (DWORD)DefDlgProcA, (DWORD)RegisterClassA, (DWORD)EndDialog, (DWORD)SetDlgItemTextA,\r\n
    (DWORD)EnumClipboardFormats, (DWORD)GetClipboardData, (DWORD)CloseClipboard, (DWORD)GetClassInfoA, (DWORD)CallWindowProcA,\r\n
    (DWORD)SetWindowLongA, (DWORD)IsDlgButtonChecked, (DWORD)SetWindowTextA, (DWORD)CheckDlgButton, (DWORD)GetActiveWindow, (DWORD)LoadCursorA,\r\n
    (DWORD)MessageBoxA, (DWORD)wsprintfA, (DWORD)GetDlgItemTextA, (DWORD)SendMessageA, (DWORD)GetCursorPos, (DWORD)TrackPopupMenu,\r\n
    (DWORD)ClientToScreen, (DWORD)DestroyMenu, (DWORD)CreatePopupMenu, (DWORD)AppendMenuA, (DWORD)SendDlgItemMessageA, (DWORD)GetDlgItem };\r\n
    \r\n
    DWORD GDI32121_Array[] = { (DWORD)GetObjectA, (DWORD)GetStockObject, (DWORD)DeleteObject, (DWORD)SetBkMode, (DWORD)SetTextColor, (DWORD)CreateFontIndirectA, (DWORD)SelectObject };\r\n
    \r\n
    DWORD comdlg3218_Array[] = { (DWORD)GetOpenFileNameA, (DWORD)GetSaveFileNameA };\r\n
    \r\n
    DWORD ADVAPI32214_Array[] = { (DWORD)RegCreateKeyA, (DWORD)RegSetValueA, (DWORD)GetUserNameA, (DWORD)RegCloseKey,\r\n
    (DWORD)RegOpenKeyExA, (DWORD)AdjustTokenPrivileges, (DWORD)LookupPrivilegeValueA, (DWORD)OpenProcessToken, (DWORD)RegQueryValueExA, (DWORD)RegDeleteKeyA };\r\n
    \r\n"""

        fake_libs = """#pragma comment(lib,\"user32.lib\")\r\n
    #pragma comment(lib,\"Comdlg32.lib\")\r\n
    #pragma comment(lib,\"UrlMon.lib\")\r\n
    #pragma comment(lib,\"Shell32.lib\")\r\n
    #pragma comment(lib,\"oledlg.lib\")\r\n
    #pragma comment(lib,\"Ole32.lib\")\r\n
    #pragma comment(lib,\"AdvApi32.lib\")\r\n
    #pragma comment(lib,\"WinInet.lib\")\r\n
    #pragma comment(lib,\"Gdi32.lib\")\r\n
    #pragma comment(lib,\"WS2_32.lib\")\r\n
    #pragma comment(lib,\"opengl32.lib\")\r\n"""

        fake_includes = """#include <intrin.h>\r\n
    #include <Objbase.h>\r\n
    #include <Callobj.h>\r\n
    #include <Shellapi.h>\r\n
    #include <Urlmon.h>\r\n
    #include <Prsht.h>\r\n
    #include <Userenv.h>\r\n"""
        
        if outfile == "../Crypter/main.cpp" :
            out.insert(0, fake_api)
            out.insert(0, static_imports)
            out.insert(0, fake_libs)
            out.insert(0, fake_includes)
        o.writelines(out)
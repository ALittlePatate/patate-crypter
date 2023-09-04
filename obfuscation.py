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

types = ["short", "unsigned short", "int", "unsigned int", "long", "unsigned long", "float", "double"]
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
    body += f"\tint bb = {GetRandomNumber()};\n"
    body += "\tfor (int i = 0; i < 10; i++) {\n\t\tCreateMutexA(NULL, false, a1);\n\t\tbb++;\n\t}\n\treturn bb;\n}"
        
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

def obfuscate(PASS, CFLOW_PASS, cflow, junk) :
    if PASS < CFLOW_PASS : PASS = CFLOW_PASS
    
    if not cflow and not junk : PASS = 0
    
    global global_vars
    global functions
    global in_func
    dont = ["for", "if", "else", "while"]
    func_def_pattern = r'\b\w+\s+\w+\s*\([^)]*\)\s*'
    
    f = open("DO_NOT_TOUCH.cpp", "r")
    o = open("main.cpp", "w")
    out = []
    
    lines = f.readlines()
    for k in range(PASS) :
        in_comment = False
        in_switch = False
        in_asm = False
        wait_for_func_close = False
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
                print(f"continue1 {in_func} {line}")
                continue
            if wait_for_func_close and "}" in line :
                in_func = False
                wait_for_func_close = False
                print(f"continue2 {in_func} {line}")
                continue
            if wait_for_func_close :
                print(f"continue3 {in_func} {line}")
                continue
            
            print(in_func, line)
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
            
            if GetRandomBool() and junk : # do we create a variable ?
                out.append(GetRandomVar()+"\n")
                
            if GetRandomBool() and in_func and junk: # do we do an operation on globals ?
                out.append(GetRandomOperation()+"\n")
            
            if GetRandomBool() and not in_func : # do we create a function ?
                out.append(GetRandomFunction()+"\n")
            
            if GetRandomBool() and in_func : # do we call a function ?
                out.append(CallRandomFunction()+"\n")
            
            if GetRandomBool() and in_func and cflow and k < CFLOW_PASS : # do we mess up control flow ?
                out.append(GetRandomAssemblyBlock()+"\n")

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

    out.insert(0, fake_api)
    out.insert(0, static_imports)
    out.insert(0, fake_libs)
    out.insert(0, fake_includes)
    o.writelines(out)
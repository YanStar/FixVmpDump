import idc
import idaapi
import idautils
import re

def Get_Code_List(ea,code_list,os_len):
    if os_len == 8:
        flag = 1
        j_flag = 1
        while (flag == 1 and j_flag == 1):
            code = idc.GetDisasm(ea)
            # print(code)
            code_list.append(str(hex(ea)) + "##" + code)
            if "retn" in code:
                break
            if "jmp     null" in code:
                break
            x_code = code[0:3]
            if "jmp" == x_code or "cal" == x_code:
                j_flag = 0
                fun_addr = "0x" + code.split("_")[1]
                ea = int(fun_addr[0:18], 16)
                Get_Code_List(ea,code_list,os_len)
            ea = idc.NextHead(ea)
    elif os_len == 4:
        flag = 1
        j_flag = 1
        while (flag == 1 and j_flag == 1):
            code = idc.GetDisasm(ea)
            code_list.append(str(hex(ea)) + "##" + code)
            if "retn" in code:
                break
            if "jmp     null" in code:
                break
            x_code = code[0:3]
            if "jmp" == x_code or "cal" == x_code:
                j_flag = 0
                if "nullsub" in code:
                    break
                elif "_" in code:
                    fun_addr = "0x" + code.split("_")[1]
                    ea = int(fun_addr[0:10], 16)
                    Get_Code_List(ea,code_list,os_len)
                else:
                    print("!!!!!Get Code Error!!!!!")
            ea = idc.NextHead(ea)

def Get_Data(reg,add_num,flag_num,hex_list,code_list,os_len):
    for x in range(flag_num, len(code_list)):
        rest_code = code_list[x].split("##")[1]
        ea = code_list[x].split("##")[0]
        mov_flag = "mov     {0}, [{1}".format(reg, reg)
        if mov_flag in rest_code:
            if "-" in rest_code:
                if "_" in rest_code:
                    op = idc.GetOperandValue(long(ea, base=16), 1)
                    int_num_1 = op
                    target_ea = add_num + int_num_1
                else:
                    num_1 = rest_code.split("-")[1].split("]")[0].split("h")[0]
                    int_num_1 = int(num_1, 16)
                    target_ea = add_num - int_num_1
                for k in range(0, os_len):
                    byte_data = idc.Byte(target_ea + k)
                    str_byte_data = str(hex(byte_data)).split("0x")[1].replace("L","")
                    if len(str_byte_data) == 1:
                        str_byte_data = "0" + str_byte_data
                    hex_list.append(str_byte_data)
                str_hex_num = ""
                for j in range(0, len(hex_list)):
                    str_hex_num = str_hex_num + hex_list[len(hex_list) - 1 - j]
                int_num_3 = int("0x" + str_hex_num, 16)
                lea_flag_1 = "lea     {0}, [{0}".format(reg, reg)
                for d in range(x, len(code_list)):
                    rest_code_1 = code_list[d].split("##")[1]
                    if lea_flag_1 in rest_code_1:
                        if "-" in rest_code_1:
                            last_num = rest_code_1.split("-")[1].split("]")[0].split("h")[0]
                            int_last_num = int(last_num, 16)
                            int_last_fun_addr = int_num_3 - int_last_num
                            hex_data = hex(int_last_fun_addr)
                            print("********************************************************************************")
                            print("***** Get Real Function Addr [{0}] Success , Fuck VMP!!!!! *****".format(hex_data))
                            print("********************************************************************************")
                            return hex_data
                        elif "+" in rest_code_1:
                            last_num = rest_code_1.split("+")[1].split("]")[0].split("h")[0]
                            int_last_num = int(last_num, 16)
                            int_last_fun_addr = int_num_3 + int_last_num
                            hex_data = hex(int_last_fun_addr)
                            print("********************************************************************************")
                            print("***** Get Real Function Addr [{0}] Success , Fuck VMP!!!!! *****".format(hex_data))
                            print("********************************************************************************")
                            return hex_data
                        else:
                            int_last_fun_addr = int_num_3
                            hex_data = hex(int_last_fun_addr)
                            print("********************************************************************************")
                            print("***** Get Real Function Addr [{0}] Success , Fuck VMP!!!!! *****".format(hex_data))
                            print("********************************************************************************")
                            return hex_data

            elif "+" in rest_code:
                if "_" in rest_code:
                    op = idc.GetOperandValue(long(ea, base=16), 1)
                    int_num_1 = op
                else:
                    num_1 = rest_code.split("+")[1].split("]")[0].split("h")[0]
                    int_num_1 = int(num_1, 16)
                target_ea = add_num + int_num_1
                #print(hex(target_ea))
                for k in range(0, os_len):
                    byte_data = idc.Byte(target_ea + k)
                    str_byte_data = str(hex(byte_data)).split("0x")[1].replace("L","")
                    if len(str_byte_data) == 1:
                        str_byte_data = "0" + str_byte_data
                    hex_list.append(str_byte_data)
                #print(hex_list)
                str_hex_num = ""
                for j in range(0, len(hex_list)):
                    str_hex_num = str_hex_num + hex_list[len(hex_list) - 1 - j]
                int_num_3 = int("0x" + str_hex_num, 16)
                lea_flag_1 = "lea     {0}, [{0}".format(reg, reg)
                for d in range(x, len(code_list)):
                    rest_code_1 = code_list[d].split("##")[1]
                    if lea_flag_1 in rest_code_1:
                        if "-" in rest_code_1:
                            last_num = rest_code_1.split("-")[1].split("]")[0].split("h")[0]
                            int_last_num = int(last_num, 16)
                            int_last_fun_addr = int_num_3 - int_last_num
                            hex_data = hex(int_last_fun_addr)
                            print("********************************************************************************")
                            print("***** Get Real Function Addr [{0}] Success , Fuck VMP!!!!! *****".format(hex_data))
                            print("********************************************************************************")
                            return hex_data
                        elif "+" in rest_code_1:
                            last_num = rest_code_1.split("+")[1].split("]")[0].split("h")[0]
                            int_last_num = int(last_num, 16)
                            int_last_fun_addr = int_num_3 + int_last_num
                            hex_data = hex(int_last_fun_addr)
                            print("********************************************************************************")
                            print("***** Get Real Function Addr [{0}] Success , Fuck VMP!!!!! *****".format(hex_data))
                            print("********************************************************************************")
                            return hex_data
                        else:
                            int_last_fun_addr = int_num_3
                            hex_data = hex(int_last_fun_addr)
                            print("********************************************************************************")
                            print("***** Get Real Function Addr [{0}] Success , Fuck VMP!!!!! *****".format(hex_data))
                            print("********************************************************************************")
                            return hex_data
            else:
                target_ea = add_num
                for k in range(0, os_len):
                    byte_data = idc.Byte(target_ea + k)
                    str_byte_data = str(hex(byte_data)).split("0x")[1].replace("L","")
                    if len(str_byte_data) == 1:
                        str_byte_data = "0" + str_byte_data
                    hex_list.append(str_byte_data)
                str_hex_num = ""
                for j in range(0, len(hex_list)):
                    str_hex_num = str_hex_num + hex_list[len(hex_list) - 1 - j]
                int_num_3 = int("0x" + str_hex_num, 16)
                lea_flag_1 = "lea     {0}, [{0}".format(reg, reg)
                for d in range(x, len(code_list)):
                    rest_code_1 = code_list[d].split("##")[1]
                    if lea_flag_1 in rest_code_1:
                        if "-" in rest_code_1:
                            last_num = rest_code_1.split("-")[1].split("]")[0].split("h")[0]
                            int_last_num = int(last_num, 16)
                            int_last_fun_addr = int_num_3 - int_last_num
                            hex_data = hex(int_last_fun_addr)
                            print("********************************************************************************")
                            print("***** Get Real Function Addr [{0}] Success , Fuck VMP!!!!! *****".format(hex_data))
                            print("********************************************************************************")
                            return hex_data
                        elif "+" in rest_code_1:
                            last_num = rest_code_1.split("+")[1].split("]")[0].split("h")[0]
                            int_last_num = int(last_num, 16)
                            int_last_fun_addr = int_num_3 + int_last_num
                            hex_data = hex(int_last_fun_addr)
                            print("********************************************************************************")
                            print("***** Get Real Function Addr [{0}] Success , Fuck VMP!!!!! *****".format(hex_data))
                            print("********************************************************************************")
                            return hex_data
                        else:
                            int_last_fun_addr = int_num_3
                            hex_data = hex(int_last_fun_addr)
                            print("********************************************************************************")
                            print("***** Get Real Function Addr [{0}] Success , Fuck VMP!!!!! *****".format(hex_data))
                            print("********************************************************************************")
                            return hex_data

def Get_Need_Addr(code_list,hex_list,os_len,flag_list):
    flag_num = 0
    reg = ""
    for m in range(0, len(code_list)):
        if "xchg" in code_list[m]:
            if len(code_list[m].split(",")[0].split("xchg")[1].strip()) != 2:
                reg = code_list[m].split(",")[0].split("xchg")[1].strip()
            for mm in range(m, len(code_list)):
                if "pop" in code_list[mm]:
                    reg = code_list[mm].split(",")[0].split("pop")[1].strip()
                else:
                    pass
        else:
            pass
    if reg == "":
        if "lea" in code_list[-2]:
            reg = code_list[-2].split(",")[0].split("lea")[1].strip()
        if "pop" in code_list[-2]:
            reg = code_list[-2].split(",")[0].split("pop")[1].strip()
    if os_len == 8:
        first_flag = "lea     " + reg
    if os_len == 4:
        first_flag = "mov     " + reg
    for i in range(0,len(code_list)):
        code = code_list[i].split("##")[1]
        if first_flag in code:
            if ":" in code:
                if ";" in code:
                    ea = code_list[i].split("##")[0]
                    op = idc.GetOperandValue(long(ea, base=16), 1)
                    add_num = op
                    fun_addr = Get_Data(reg, add_num, i, hex_list, code_list, os_len)
                    return fun_addr
                else:
                    pass
            elif "[" in code:
                pass
            elif "*" in code:
                pass
            elif "ax" in code.split(",")[1]:
                if len(code.split(",")[1]) < 4:
                    pass
                else:
                    flag_list.append(code_list[i])
                    flag_num = i
            elif "bx" in code.split(",")[1]:
                if len(code.split(",")[1]) < 4:
                    pass
                else:
                    flag_list.append(code_list[i])
                    flag_num = i
            elif "cx" in code.split(",")[1]:
                if len(code.split(",")[1]) < 4:
                    pass
                else:
                    flag_list.append(code_list[i])
                    flag_num = i
            elif "dx" in code.split(",")[1]:
                if len(code.split(",")[1]) < 4:
                    pass
                else:
                    flag_list.append(code_list[i])
                    flag_num = i
            elif "si" in code.split(",")[1]:
                if len(code.split(",")[1]) < 4:
                    pass
                else:
                    flag_list.append(code_list[i])
                    flag_num = i
            elif "di" in code.split(",")[1]:
                if len(code.split(",")[1]) < 4:
                    pass
                else:
                    flag_list.append(code_list[i])
                    flag_num = i
            elif "r8" in code.split(",")[1]:
                if len(code.split(",")[1]) < 4:
                    pass
                else:
                    flag_list.append(code_list[i])
                    flag_num = i
            elif "r9" in code.split(",")[1]:
                if len(code.split(",")[1]) < 4:
                    pass
                else:
                    flag_list.append(code_list[i])
                    flag_num = i
            else:
                flag_list.append(code_list[i])
                flag_num = i
    ea = flag_list[-1].split("##")[0]
    op = idc.GetOperandValue(long(ea,base=16) , 1)
    add_num = op
    fun_addr = Get_Data(reg, add_num, flag_num,hex_list,code_list,os_len)
    return fun_addr

def Fix_Fun_Name(ea,db_path,fun_addr):
    find_flag = 0
    with open(db_path,"r") as fr:
        for line in fr.readlines():
            if fun_addr in line:
                fun_name = line.split(" ")[0]
                idc.set_name(ea, fun_name, idaapi.SN_FORCE)
                print("********************************************************************************")
                print("***** Rename Function Name [{0}] Success , Fuck VMP!!!!! *****".format(fun_name))
                print("********************************************************************************")
                find_flag = 1
            else:
                pass
    if find_flag == 0:
        print("********************************************************************************")
        print("***** Not Find Function Name , Fuck VMP!!!!! *****".format(fun_name))
        print("********************************************************************************")



def Run():
    hex_list = []
    code_list = []
    flag_list = []
    ea = idc.ScreenEA()

    if(len(str(hex(ea)))) < 15:
        os_len = 4
        read_db_path = "D:\\fix_vmp_dump\\ntkrnlpa.txt"
    else:
        os_len = 8
        read_db_path = "D:\\fix_vmp_dump\\ntoskrnl.txt"
    fun_addr = "0x" + idc.GetDisasm(ea).split("_")[1]
    ea = int(fun_addr,16)
    Get_Code_List(ea,code_list,os_len)
    fun_addr = Get_Need_Addr(code_list,hex_list,os_len,flag_list)
    Fix_Fun_Name(ea,read_db_path,fun_addr)

def Run_2():
    for func in idautils.Functions():
        hex_list = []
        code_list = []
        flag_list = []
        ea = idc.ScreenEA()

        if(len(str(hex(ea)))) < 15:
            os_len = 4
            read_db_path = "D:\\fix_vmp_dump\\ntkrnlpa.txt"
        else:
            os_len = 8
            read_db_path = "D:\\fix_vmp_dump\\ntoskrnl.txt"
        try:
            Get_Code_List(func,code_list,os_len)
            fun_addr = Get_Need_Addr(code_list,hex_list,os_len,flag_list)
            Fix_Fun_Name(func,read_db_path,fun_addr)
        except:
            pass


def registerHotkey(shortcut):
    idaapi.CompileLine(r'static Run() { RunPythonStatement("Fix_Vmp_Dump_API.Run()"); }')
    idc.AddHotkey(shortcut, "Run")

def registerHotkey_2(shortcut):
    idaapi.CompileLine(r'static Run_2() { RunPythonStatement("Fix_Vmp_Dump_API.Run_2()"); }')
    idc.AddHotkey(shortcut, "Run_2")

# fix single api name
keyname = "Shift-F"
registerHotkey(keyname)

# fix all api name use carefully
keyname = "Shift-G"
registerHotkey_2(keyname)
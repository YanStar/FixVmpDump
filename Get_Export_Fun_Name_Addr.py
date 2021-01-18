import os
import idc
import idaapi
import binascii

idb_path = idc.get_idb_path()

if ".idb" in idb_path:
    export_table_file_name = idb_path.split(".idb")[0].split("\\")[-1] + ".txt"
elif ".i64" in idb_path:
    export_table_file_name = idb_path.split(".i64")[0].split("\\")[-1] + ".txt"
elif ".dll" in idb_path:
    export_table_file_name = idb_path.split(".dll")[0].split("\\")[-1] + ".txt"
else:
    export_table_file_name = idb_path.split("\\")[-1] + ".txt"

out_path = "D:\\fix_vmp_dump"

if not os.path.exists(out_path):
    os.makedirs(out_path)

file_name = out_path + "\\" + export_table_file_name
if os.path.exists(file_name):
    os.remove(file_name)

count = idc.get_entry_qty()
with open(file_name,"a") as fa:
    for i in range(0,count-1):
        try:
            fa.write(idc.get_entry_name(idc.get_entry_ordinal(i)) + " " + hex(idc.get_entry(idc.get_entry_ordinal(i))) + "\n")
        except:
            pass
print("Write Export Table Info To {0} Success!".format(file_name))
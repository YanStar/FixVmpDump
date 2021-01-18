# FixVmpDump
use python script to fix vmp dump api in ida

# step 1
(1) open need moudle by ida and run "Get_Export_Fun_Name_Addr.py". you can get "xxx.txt" in your "D:\fix_vmp_dump\".

# step 2
(1) put "Fix_Vmp_Dump_API.py" in your "%ida%/python/".  
(2) insert "**import Fix_Vmp_Dump_API**" to your "%ida%/python/init.py" file, like this:

    try:
      import ida_idaapi
      import ida_kernwin
      import ida_diskio
      import Fix_Vmp_Dump_API
    
     except ImportError as e:
      print "Import failed: %s. Current sys.path:" % str(e)
      for p in sys.path:
          print "\t%s" % p
      raise
 
(3) restart your ida

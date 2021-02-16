import os
from tqdm import tqdm
import glob
import pefile
# import cxxfilt  # only for linux
import subprocess
import shutil
import sys
import json

class DependencyChecker(object):
    def __init__(self):
        self.system_path = []
        self.dllnames = []
        self.missing_dlls = {}
        self.missing_statistics = {}
        self.file_deps = {}
        self.file_deps["good"] = 0
        self.file_deps["bad"] = 0
        self.dependency_stats = {}
        with open("default_dlls.txt", "r") as file:
            default_dlls = file.readlines()
            for i in range(len(default_dlls)):
                default_dlls[i] = default_dlls[i].replace("\n", "") 
        self.default_dlls = set(default_dlls)
    def read_env_variables(self):
        env = os.getenv("PATH").split(";")
        extensions = ["dll", "drv", "cpl", "ocx", "exe16"]
        for ext in extensions:
            for envpath in env:
                for item in glob.glob(envpath + "\\*."+ext):
                    dllname = os.path.basename(item).lower()
                    if dllname not in self.dllnames:
                        self.dllnames.append(dllname)
        
        # with open("default_dlls-2.txt", 'w') as file:
        #     for dll in self.dllnames:
        #         file.write(dll + '\n')
        # exit(1)    

    def enum_imported_dll(self, pn):
        print("working on %s" % pn)
        pe = pefile.PE(pn)
        pe.parse_data_directories()

        split_pn = pn.split("\\")
        mw_hash = split_pn[len(split_pn) - 1]
        self.dependency_stats[mw_hash] = {"required":[], "installed": [], "fakedll": []}
        mw_stats = self.dependency_stats[mw_hash]
        missing = False
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dllname = entry.dll.decode("utf-8").lower()
            print(dllname)
            with open("imports.txt", "a") as file:
                file.write(dllname+'\n')
            
            if dllname not in self.dllnames:
                print(dllname)  
                mw_stats['required'].append(dllname)
                print("[*] Found missing dll %s" % dllname)
                missing = True

                # put that into dictionary
                if dllname not in self.missing_statistics.keys():
                    self.missing_statistics[dllname] = 1
                else:
                    self.missing_statistics[dllname] += 1

                # update dll's imported functions
                self.missing_dlls[dllname] = []
                for imp in entry.imports:
                    if imp.name is not None:
                        imported_func = imp.name.decode("utf-8")
                        if imported_func not in self.missing_dlls[dllname]:
                            # print(imported_func)
                            self.missing_dlls[dllname].append(imported_func)
            else:
                if dllname not in self.default_dlls:
                    mw_stats['installed'].append(dllname)

        if missing is True:
            self.file_deps["bad"] += 1
        else:
            self.file_deps["good"] += 1

        pe.close()

def check_malware_deps(pn=None):
    dc = DependencyChecker()
    dc.read_env_variables()
    dc.enum_imported_dll(pn)
    print(dc.missing_dlls)
    print(dc.missing_statistics)


def main():
    # # dc = DependencyChecker()
    # # dc.read_env_variables()
    # # env = dc.dllnames
    # # with open("table1.json", 'r') as file:
    # #     table1 = json.loads(file.read())
    # #     for key in table1:
    # #         if key in env:
    # #             print(key)
    # # exit(1)
    # # arr2 = []
    # # arr = ['winspool.drv', 'bthprops.cpl', 'hhctrl.ocx', 'winspool.drv', 'winspool.drv', 'krnl386.exe16', 'winspool.drv', 'ntdll', 'rtl70.bpl', 'dbrtl70.bpl', 'vcl70.bpl', 'indy70.bpl', 'vclx70.bpl', 'bdertl70.bpl', 'tdbf_d7r.bpl', 'vcldb70.bpl', 'vclsmp70.bpl', 'irprops.cpl', 'hhctrl.ocx', 'rtl100.bpl', 'vcl100.bpl', 'vclx100.bpl', 'vclsmp100.bpl', 'user32.dll', 'setupapi.dll', 'ws2_32.dll']
    # # for deps in arr:
    # #     # if "." not in deps:
    # #     #     print(deps)
    # #     #     continue
    # #     if deps in env:
    # #         print("[INSTALLED] " + deps)
    # #         arr2.append(deps)
    # #     else:
    # #         print("[NOT INSTALLED] " + deps)
    # # print(arr2)
    # # exit(1)
    # dc = DependencyChecker()
    # dc.read_env_variables()
    # with open("64dll\\table2_64dll.json", 'r') as file:
    #     json_dump = json.loads(file.read())
    #     for mw_hash in json_dump:
    #         req_dll = json_dump[mw_hash]
    #         for dll in req_dll:
    #             if dll in env:
    #                 print(dll)
    #                 req_dll.remove(dll)
    
    # with open("missing_extensions.json", 'r') as file:
    #     lines = json.loads(file.read())
    # for key in lines:
    #     # key = malware hash
        
    #     dc.enum_imported_dll("..\\file-feed\\"+"c86ecb40c73a4018cd232de9132573d47105d9e562b4d22ef29527d831185208.exe")
    #     break
    # print(dc.missing_statistics)
        


    # check_malware_deps("..\\file-feed\\05682bb139d28c564bfe2078b12658f04fd954af692d60a78820f194951776f9.exe")

    # exit(1)
    if len(sys.argv) < 3 or (sys.argv[1] not in ["32", "64"]) or (sys.argv[2] not in ["exe", "dll"]):
        print("\n\n[USAGE] python update_dll_table.py [32 or 64] [dll or exe]\n\n")
        exit(1)

    mw_bit = sys.argv[1]
    mw_extension = sys.argv[2]

    mw_dir_path = "..\\file-feed"
    dc = DependencyChecker()
    dc.read_env_variables()
    # files = glob.glob(LISTEN_FILES + "\\*.dll")

    lines = None
    with open("{}{}.txt".format(mw_bit, mw_extension), 'r') as f:
        lines = f.readlines()

    for line in tqdm(lines):
        try:
            mw_file_path = mw_dir_path + "\\{}".format(line.strip())
            print(mw_file_path)
            dc.enum_imported_dll(mw_file_path)
        except AttributeError as err:
            print(err)
            with open("error_mw.txt", 'a') as file:
                file.write(malwares[i].strip() + '.' + mw_extension +"\n")

            
    with open("table2_{}{}.json".format(mw_bit, mw_extension), 'w') as file:
        json_dump = json.dumps(dc.dependency_stats, indent=4)
        file.write(json_dump)
    with open("table1_{}{}.json".format(mw_bit, mw_extension), 'w') as file:
        file.write(json.dumps(dc.missing_statistics, indent=4))
        # with open("deps_table.txt", "a") as file:
            






if __name__ == '__main__':
    main()
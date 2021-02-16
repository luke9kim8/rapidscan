import json
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
            print(entry.dll.decode("utf-8"))
            with open("imports.txt", "a") as file:
                file.write(dllname+'\n')
            if dllname not in self.default_dlls:
                mw_stats["required"].append(dllname)
            
            if dllname not in self.dllnames:
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

def read_from_json(pn=None):
    dict_name = None
    with open(pn, 'r') as file:
        dict_name = json.loads(file.read())
    return dict_name

def write_to_json(pn=None, dict_name=None):
    with open(pn, 'w') as file:
        file.write(json.dumps(dict_name, indent=4, sort_keys=True))
def update_table2(installed_dlls=None):
    table2 = read_from_json("table2.json")
    for mw_hash in table2:
        req_dll = table2[mw_hash]['required']
        inst_dll = table2[mw_hash]['installed']
        for installed_dll in installed_dlls:
            if installed_dll in req_dll and installed_dll not in inst_dll:
                inst_dll.append(installed_dll)
    write_to_json("table2-updated.json", table2)

def find_mw_with_deps():
    table2 = read_from_json("table2_updated.json")
    new_table2 = {}
    for key in table2:
        if len(table2[key]['required']) > 0:
            new_table2[key] = table2[key]
    write_to_json("mw_with_deps.json", new_table2)

def find_mw_with_no_deps():
    table2 = read_from_json("table2_with_type.json")
    no_deps_exe = {}
    no_deps_dll = {}
    crtdll_exe = {}
    crtdll_dll = {}
    for mw_hash in table2:
        req_dll = table2[mw_hash]['required']
        mw_type = table2[mw_hash]["type"]
        if "exe" in mw_type:
            if len(req_dll) == 0:
                no_deps_exe[mw_hash] = table2[mw_hash]
            elif "crtdll.dll" in req_dll and len(req_dll) == 1:
                crtdll_exe[mw_hash] = table2[mw_hash]
        elif "dll" in mw_type:
            if len(req_dll) == 0:
                no_deps_dll[mw_hash] = table2[mw_hash]
            elif "crtdll.dll" in req_dll and len(req_dll) == 1:
                crtdll_dll[mw_hash] = table2[mw_hash]
        else:
            print("{} does not have type".format(mw_hash))
        
    write_to_json("crtdll_exe.json", crtdll_exe)
    print("crtdll_exe: ", len(crtdll_exe.keys()))
    write_to_json("crtdll_dll.json", crtdll_dll)
    print("crtdll_dll: ", len(crtdll_dll.keys()))
    write_to_json("no_deps_exe.json", no_deps_exe)
    print("no_deps_exe: ", len(no_deps_exe.keys()))
    write_to_json("no_deps_dll.json", no_deps_dll)
    print("no_deps_dll: ", len(no_deps_dll.keys()))
    crt_32 = 0
    crt_64 = 0
    none_32 = 0
    none_64 = 0

    for mw_hash in crtdll_exe:
        if "32" in crtdll_exe[mw_hash]['type']:
            crt_32 += 1
        else:
            crt_64 += 1
    for mw_hash in no_deps_exe:
        if "32" in no_deps_exe[mw_hash]['type']:
            none_32 += 1
        else:
            none_64 += 1
    print("crt32: ", crt_32)
    print("crt64: ", crt_64)
    print("none32", none_32)
    print("none64", none_64)

def arr_equal(arr1, arr2):
    if len(arr1) != len(arr2):
        return False
    for a in arr1:
        if a not in arr2:
            return False
    return True

def find_malwares_w_unmet_deps():
    table2 = read_from_json("updated/(update)table2_with_type.json")
    unsatisfied_exe = {}
    unsatisfied_dll = {}
    no_type = {}
    for mw_hash in table2:
        req_dll = table2[mw_hash]['required']
        inst_dll = table2[mw_hash]['installed']
        mw_type = table2[mw_hash]['type']

        if arr_equal(req_dll, inst_dll) == False:
            if "exe" in mw_type:
                unsatisfied_exe[mw_hash] = table2[mw_hash]
            elif "dll" in mw_type:
                unsatisfied_dll[mw_hash] = table2[mw_hash]
            else:
                no_type[mw_hash] = table2[mw_hash]

    write_to_json("mw_with_deps_exe.json", unsatisfied_exe)
    write_to_json("mw_with_deps_dll.json", unsatisfied_dll)
    print("{} more exes to go!".format(len(unsatisfied_exe.keys())))
    print("{} more dlls to go!".format(len(unsatisfied_dll.keys())))
    if len(no_type.keys()) > 0:
        print("there's no type??? What??")
        print(no_type)
        


def main():
    if len(sys.argv) == 1:
        find_malwares_w_unmet_deps()
        exit(1)
    print("Looking for new dlls...")
    dc = DependencyChecker()
    dc.read_env_variables()

    program_name = sys.argv[1]
    link = sys.argv[2]

    table1 = read_from_json('table1.json')
    table2 = read_from_json("table2_with_type.json")

    for mw_hash in table2:
        req_dll = table2[mw_hash]['required']
        inst_dll = table2[mw_hash]['installed']
        
        for dll in req_dll:
            if dll in dc.dllnames and dll not in inst_dll: # if dll in env variables but not installed
                table2[mw_hash]['installed'].append(dll)
                table1[dll]["Program"] = program_name
                table1[dll]["link"] = link
                print("Installed {}".format(dll))
                if arr_equal(table2[mw_hash]['required'], table2[mw_hash]['installed']):
                    print("This has all deps satisfied (down)")
                    print(mw_hash)
                    
    

        
    write_to_json("table2_with_type.json", table2)
    write_to_json("table1.json", table1)

    find_malwares_w_unmet_deps()
main()
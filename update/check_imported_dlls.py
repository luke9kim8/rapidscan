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
def read_from_json(pn=None):
    dict_name = None
    with open(pn, 'r') as file:
        dict_name = json.loads(file.read())
    return dict_name

def write_to_json(pn=None, dict_name=None):
    with open(pn, 'w') as file:
        file.write(json.dumps(dict_name, indent=4, sort_keys=True))


def main():
    # C:\Windows\SysWOW64\
    



    exit(1)
    installed_dlls = ["liveupdate.dll" "cximage.dll",
            "libeay32.dll",
            "ssleay32.dll",
            "sgbdmyss.dll",
            "7zpp_a.dll"]
    found_all = True
    for dll in installed_dlls:
        if dll not in dc.dllnames:
            print(dll + " found!")
        else:
            print(dll + " does not exist!")
            found_all = False
    
    if found_all:
        print("All dlls found!")
    else:
        print("Some deps not met!")
main()
    

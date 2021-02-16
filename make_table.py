import os
from tqdm import tqdm
import sys
import json

def make_32bitdll_table2():
    per_mw_fs = "| {} | 32 | DLL |  | {} |  |  |"
    with open("per_mw_deps_32dll.txt", 'r') as file:
        json_dump = file.read().strip("\n")
        mw_deps = json.loads(json_dump)
        for mw_hash in mw_deps:
            mw_stats = mw_deps[mw_hash]
            with open("table2_32dll.txt", 'a') as table_file:
                table_file.write(per_mw_fs.format(mw_hash, len(mw_stats["required"])) + '\n')
def make_32bitdll_table1():
    deps_fs = "| {} |  |  | {} |  |\n"
    with open("missing_stats.txt", 'r') as file:
        json_dump = file.read()
        deps = json.loads(json_dump)
        with open("table1_32dll.txt", 'a') as table_file:
            for dep in deps:
                table_file.write(deps_fs.format(dep, deps[dep]))
def make_table1(bit, extension):
    deps_fs = "| {} |  |  | {} |  |\n"
    with open("table1_{0}{1}.json".format(bit, extension), 'r') as file:
        json_dump = file.read()
        deps = json.loads(json_dump)
        with open("table1_{0}{1}.txt".format(bit, extension), 'a') as table_file:
            for dep in deps:
                table_file.write(deps_fs.format(dep, deps[dep]))       
def make_table2(bit, extension):
    per_mw_fs = "| {} | {} | {} |  | {} |  |  |"
    with open("table2_{0}{1}.json".format(bit, extension), 'r') as file:
        json_dump = file.read().strip("\n")
        mw_deps = json.loads(json_dump)
        for mw_hash in mw_deps:
            mw_stats = mw_deps[mw_hash]
            with open("table2_{0}{1}.txt".format(bit, extension), 'a') as table_file:
                table_file.write(per_mw_fs.format(mw_hash, bit, extension, len(mw_stats["required"])) + '\n')         

def make_giant_table1():
    fp_arr = [
        ["32", "dll"],
        ["32", "exe"],
        ["64", "dll"],
        ["64", "exe"]
    ]
    missing_stats = {}
    deps_fs = "| {} |  |  | {} |  |\n"

    for fp in fp_arr:
        fp = "{0}{1}\\table1_{0}{1}.json".format(fp[0], fp[1])
        with open(fp, 'r') as file:
            json_dump = file.read()
            table1_json = json.loads(json_dump)
            for key in table1_json:
                if key not in missing_stats:
                    missing_stats[key] = table1_json[key]
                else:
                    missing_stats[key] += table1_json[key]

    with open("giant_table1.txt", 'a') as file:
        for key in missing_stats:
            file.write(deps_fs.format(key, missing_stats[key]))
    print('yo')
    print(len(missing_stats.keys()))

def make_giant_table1_json():
    arr = [
        ["32", "exe"],
        ["32", "dll"],
        ["64", "dll"],
        ["64", "exe"]
    ]
    table1 = {}
    for bits_ext in arr:
        bit = bits_ext[0]
        ext = bits_ext[1]
        with open("{0}{1}\\table2_{0}{1}-2.json".format(bit, ext), 'r') as file:
            table2 = json.loads(file.read())
            for mw_hash in table2:
                req_dll = table2[mw_hash]["required"]
                for dll in req_dll:
                    if dll in table1:
                        table1[dll] += 1
                    else:
                        table1[dll] = 1
    with open("table1.json", 'w') as file:
        file.write(json.dumps(table1))

def main():
    arr = [
        ["32", "exe"],
        ["32", "dll"],
        ["64", "dll"]
    ]
    for bits_ext in arr:
        bit = bits_ext[0]
        ext = bits_ext[1]
        make_table1(bit, ext)
        make_table2(bit, ext)
    exit(1)
    if len(sys.argv) < 3 or (sys.argv[1] not in ["32", "64"]) or (sys.argv[2] not in ["exe", "dll"]):
        print("\n\n give valid inputs \n\n")
        exit(1)
    


            

if __name__ == '__main__':
    main()      
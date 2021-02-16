import json
import os



mws = os.listdir("..\\file-feed")
print(len(mws))
no_ext = 0
count = 0

for mw in mws:
    if ".exe" not in mw and ".dll" not in mw:
        no_ext += 1
        cmd_str = "\"C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Tools\\MSVC\\14.28.29333\\bin\\Hostx64\\x86\\dumpbin\" ..\\file-feed\\{} /headers".format(mw)
        res = os.popen(cmd_str).read()
        if "(PE32)" in res:
            if "File Type: EXECUTABLE IMAGE" in res:
                with open("leftover\\32bit_exe.txt", 'a') as file:
                    file.write(mw+'\n')
            elif "File Type: DLL" in res:
                with open("leftover\\32bit_dll.txt", 'a') as file:
                    file.write(mw+'\n')
            else:
                count += 1
                with open("leftover\\{}.txt".format(mw), 'a') as file:
                    file.write(res)
        elif "(PE32+)" in res:
            if "File Type: EXECUTABLE IMAGE" in res:
                with open("leftover\\64bit_exe.txt", 'a') as file:
                    file.write(mw+'\n')
            elif "File Type: DLL" in res:
                with open("leftover\\64bit_dll.txt", 'a') as file:
                    file.write(mw+'\n')
            else:
                count += 1
                with open("leftover\\{}.txt".format(mw), 'a') as file:
                    file.write(res)
        else:
            count += 1
            with open("leftover\\{}.txt".format(mw), 'a') as file:
                    file.write(res)
print(no_ext)
print(count)         
        
exit(1)
# missing_extensions = None

# with open("missing_extensions.json", 'r') as file:
#     missing_extensions = json.loads(file.read())

# rows = None
# with open("\\32exe\\table2_32exe.txt", 'r') as file:
#     rows = file.readlines()

# with open("\\32exe\\table2_32exe.txt", 'a') as file:
#     fs = "| {} | 32 | exe |  | 0 |  |  |"
#     file.write("\n\n--------------------------------\n\n")
#     for row in rows:
#         mw_hash = row.split("|")[1].strip()
#         if mw_hash in missing_extensions:
#             file.write(fs.format(mw_hash))
#         else:
#             file.write(row)

installed = ['winspool.drv', 'bthprops.cpl', 'hhctrl.ocx', 'winspool.drv', 'winspool.drv', 'winspool.drv', 'irprops.cpl', 'hhctrl.ocx', 'user32.dll', 'setupapi.dll', 'ws2_32.dll']
    
def chage_table2_json(bit, ext):
    with open("{0}{1}\\table2_{0}{1}.json".format(bit, ext), 'r') as file:
        # print("-------------------------------------64exe")
        table2 = json.loads(file.read())
        for key in table2:
            req_dll = table2[key]['required']
            i = 0
            while (i < len(req_dll)):
                if req_dll[i] in installed:
                    req_dll.remove(req_dll[i])
                    i -= 1
                i+=1
        with open("{0}{1}\\table2_{0}{1}.json-2".format(bit, ext), 'w') as file:
            file.write(json.dumps(table2))

arr = [
    ["32", "dll"],
    ["64", "dll"],
    ["64", "exe"]
]

for bits_ext in arr:
    chage_table2_json(bits_ext[0], bits_ext[1])







exit(1)

arr = []
with open("64exe\\table1_64exe.json", 'r') as file:
    print("-------------------------------------64exe")
    table1 = json.loads(file.read())
    for deps in table1:
        if '.dll' not in deps:
            print(deps)
            arr.append(deps)
with open("64dll\\table1_64dll.json", 'r') as file:
    print("-------------------------------------64dll")
    table1 = json.loads(file.read())
    for deps in table1:
        if '.dll' not in deps:
            print(deps)
            arr.append(deps)
with open("32dll\\table1_32dll.json", 'r') as file:
    print("-------------------------------------32dll")
    table1 = json.loads(file.read())
    for deps in table1:
        if '.dll' not in deps:
            print(deps)
            arr.append(deps)
with open("32exe\\table1_32exe.json", 'r') as file:
    print("-------------------------------------32exe")
    table1 = json.loads(file.read())
    for deps in table1:
        if '.dll' not in deps:
            print(deps)
            arr.append(deps)
print(arr)


# with open("\\64exe\\table2_64exe.json", 'r') as file:
#     table2_64exe = json.loads(file.read())

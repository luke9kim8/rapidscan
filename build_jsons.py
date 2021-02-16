import json
import os


# table1_2 = {}
# with open("table1_2.txt", 'r') as file_1:
#     for line in file_1.readlines():
#         dllname = line.split("|")[1].strip()
#         count = line.split("|")[4].strip()
#         table1_2[dllname] = count
# table1_1 = {}
# with open("table1.txt", 'r') as file_1:
#     for line in file_1.readlines():
#         dllname = line.split("|")[1].strip()
#         count = line.split("|")[4].strip()
#         table1_1[dllname] = count
# for dll in table1_1:
#     if dll not in table1_2:
#         print(dll)
#     elif table1_2[dll] != table1_1[dll]:
#         print("count", dll)

# exit(1)
# create 32exe_json
def initialize():
    pn_1 = "leftover\\table2_32exe.json"
    pn_2 = "32exe\\table2_32exe-2.json"
    json_1 = None
    json_2 = None
    with open(pn_1, 'r') as file_1:
        json_1 = json.loads(file_1.read())
        print(len(json_1.keys()))
    with open(pn_2, 'r') as file_1:
        json_2 = json.loads(file_1.read())
        print(len(json_2.keys()))
    table2_32exe = {**json_1, **json_2}

    pn_1 = "32dll\\table2_32dll-2.json"
    with open(pn_1, 'r') as file_1:
        json_1 = json.loads(file_1.read())
        print(len(json_1.keys()))
    table2_32dll = json_1

    pn_1 = "64dll\\table2_64dll-2.json"
    with open(pn_1, 'r') as file_1:
        json_1 = json.loads(file_1.read())
        print(len(json_1.keys()))
    table2_64dll = json_1

    pn_1 = "64exe\\table2_64exe-2.json"
    with open(pn_1, 'r') as file_1:
        json_1 = json.loads(file_1.read())
        print(len(json_1.keys()))
    table2_64exe = json_1

    table2 = {**table2_32dll, **table2_32exe, **table2_64dll, **table2_64exe}

    with open("table2.json", 'w') as file:
        file.write(json.dumps(table2))
    print(len(table2.keys()))
    table1 = {}

    for mw_hash in table2:
        req_dll = table2[mw_hash]['required']
        for dll in req_dll:
            if dll in table1:
                table1[dll] += 1
            else:
                table1[dll] = 1
    with open("table1.json", 'w') as file:
        file.write(json.dumps(table1))




# print(len(table1.keys()))
# deps_fs = "| {} |  |  | {} |  |\n"
# with open("table1.txt", 'a') as file:
#     for dll in table1:
#         file.write(deps_fs.format(dll, table1[dll]))


    


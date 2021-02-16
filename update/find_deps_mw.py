import json

def read_from_json(pn=None):
    dict_name = None
    with open(pn, 'r') as file:
        dict_name = json.loads(file.read())
    return dict_name

def write_to_json(pn=None, dict_name=None):
    with open(pn, 'w') as file:
        file.write(json.dumps(dict_name, indent=4, sort_keys=True))


def main():
    deps = read_from_json("uptdated\\(update)table2.json")
    
    table2 = read_from_json("updated\\(update)table2_with_type.json")
    exe = {}
    for mw_hash in table2:
        mw_type = table2[mw_hash]['type']
        if "exe" in mw_type and "crtdll.dll" not in table2[mw_hash]['required'] and len(table2[mw_hash]['required']) > 0:
            exe[mw_hash] = table2[mw_hash]
    write_to_json("mw_with_deps_exe.json", exe)
main()
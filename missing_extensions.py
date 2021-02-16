import os
import json
fp_arr = [
        ["32", "dll"],
        ["32", "exe"],
        ["64", "dll"],
        ["64", "exe"]
    ]
missing_stats = {}
deps_fs = "| {} |  |  | {} |  |\n"
no_extensions = {}
for fp in fp_arr:
    fp = "{0}{1}\\table2_{0}{1}.json".format(fp[0], fp[1])
    with open(fp, 'r') as file:
        json_dump = file.read()
        table2_json = json.loads(json_dump)
        for key in table2_json:
            deps = table2_json[key]['required']
            for dep in deps:
                if "." not in dep and key not in no_extensions:
                    no_extensions[key] = [dep]
                elif key in no_extensions:
                    print("ye")
                    no_extensions[key].append(dep)
with open("missing_extensions.txt", 'w') as file:
    jsondump = json.dumps(no_extensions)
    jsondump = jsondump.replace(',' ,',\n')
    file.write(jsondump)

                

import os
import subprocess
from tqdm import tqdm

def main():
    path = "..\\file-feed"
    malwares = os.listdir(path)
    print(len(malwares))
    for i in tqdm(range(10000)):
        path = "..\\file-feed\\{}".format(malwares[i])
        # proc = subprocess.run("file -b {}".format(path))
        # print(proc)
        # print(proc.stdout)
        res = os.popen("file -b "+path).read()
        if ".dll" in path or ".exe" in path:
            continue
        if "PE32+" in res: # if 64bit
            if "DLL" in res: # if .dll
                os.rename(path, path + '.dll')
                with open("64bit_dll.txt", 'a') as f:
                    f.write(malwares[i] + '\n')
            elif "console" in res or "GUI" in res: # if .exe
                os.rename(path, path + '.exe')
                with open("64bit_exe.txt", 'a') as f:
                    f.write(malwares[i] + '\n')
        elif "PE32" in res: # if 32bit
            if "DLL" in res: # if .dll
                os.rename(path, path + '.dll')
                with open("32bit_dll.txt", 'a') as f:
                    f.write(malwares[i] + '\n')
            elif "console" in res or "GUI" in res: # if .exe
                os.rename(path, path + '.exe')
                with open("32bit_exe.txt", 'a') as f:
                    f.write(malwares[i] + '\n')
        else:
            with open("wat.txt", 'a') as f:
                    f.write(malwares[i] + '\n')
                    


        
    

if __name__ == '__main__':
    main()      
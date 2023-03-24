import subprocess 

def scan(command: str) -> str:
    cmd = command
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, err = p.communicate()
    out = out.decode() 
    return out

def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass
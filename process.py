import re
import os
import json

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

    # Remove comments
    file_contents = re.sub(r"#.*\n", "\n",   file_contents)

    # Hardcode webhook
    file_contents =  file_contents.replace("%webhook%", os.getenv("DISCORD_WEBHOOK"))
    
    # Write to stub.o.py
    with open('stub.o.py', "w") as out_file:
        out_file.write(file_contents)
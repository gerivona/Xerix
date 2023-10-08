import subprocess
import os
from Xerix import commands

try:

    while True:
        
        cwd = os.getcwd() 

        strc = cwd + ">"

        run = input(strc)

        subprocess.run(run,shell=True)

        if run == "exit":
            commands()

except KeyboardInterrupt:
    commands()

    # How do i import the only the commands function from xerix without showing the whole  xerix code
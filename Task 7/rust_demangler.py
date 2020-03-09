# Attempts to demangle function names from compiled Rust code.
#@author Zack Elia
#@category Symbol
#@keybinding 
#@menupath 
#@toolbar 

import os
import subprocess

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

# Ghidra uses a different PATH variable which does not include Rust packages
rustfilt_path = "{}/.cargo/bin/rustfilt".format(os.environ.get("HOME")) 

if not os.path.exists(rustfilt_path):
    # TODO: Make this run without rustfilt as backup
    print "Could not find {}. Try `cargo install rustfilt`".format(rustfilt_path)
    exit(-1)

function_manager = currentProgram.getFunctionManager()
functions = function_manager.getFunctions(True)

for function in functions:
    demangled = subprocess.check_output([rustfilt_path, function.getName()]).strip()

    # Remove the namespaces from functions
    if "::" in demangled or demangled != function.name:
        parts = demangled.split("::")

        name = parts[-1]
        # The real name is either last or second to last succeeded by an "h" and a 16 character hash
        if len(name) == 17 and name[0] == "h":
            name = parts[-2]
    
    elif len(function.getName()) == 17 and function.getName()[0] == "h":
        # Function names that are just hashes have the real name in the plate comment
        comment = function.getComment()

        if not comment:
            continue

        name = comment.split("::")[-2]
    
    else:
        continue

    function.setName(name, SourceType.ANALYSIS)

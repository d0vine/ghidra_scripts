#Export unsafe function references
#@author: Krzysztof '_0kami' Marciniak (F-Secure)
#@category Functions
import csv
import re

MAX_ARGS = 5

unsafe = {				# arg count
	"memcpy":			3,
	"_memcpy":			3,
	"memmove":			3,
	"_memmove":			3,
	"RtlCopyMemory":		3,
	"RtlMoveMemory":		3,
	"RtlCopyBytes":			3,
	"RtlZeroMemory":		2,
	"RtlFillMemory":		3,
	"RtlFreeUnicodeString":		1,
	"RtlFreeAnsiString":		1,
	"RtlAnsiStringToUnicodeString":	3
}

out_lines = []

listing = currentProgram.getListing()
function = getFirstFunction()
while function is not None:
    func_name = function.getName()
    for banned in unsafe:
        if func_name == banned:
            refs = [ref for ref in getSymbols(func_name, None)[0].getReferences()]
            for ref in refs:
                func = getFunctionContaining(ref.fromAddress)	# collect unique ones
                parent_func_name = func.name
                decomp_interface = ghidra.app.decompiler.DecompInterface()
                decomp_interface.openProgram(currentProgram)
                decomp_results = decomp_interface.decompileFunction(func, 30, monitor)

                if decomp_results.decompileCompleted():
                    decompiled = decomp_results.getDecompiledFunction()
                    code = decompiled.getC()
                    arg_count = unsafe[func_name]
                    args = "[ \t\n]*,[ \t\n]*".join(["(.*)"] * arg_count)
                    regex = r"{}\({}\);".format(func_name, args)
                    # print regex
                    matches = re.findall(regex, code)
                    params = list(matches[0]) if matches else []
                    # print params
                    out_params = params + [""] * (MAX_ARGS - arg_count)

                    out_lines.append([func_name, "0x{}".format(ref.fromAddress), parent_func_name] + out_params)
                    
                    #print "%s found at %s" % (function.getName(),function.getEntryPoint())
    function = getFunctionAfter(function)

with open('/tmp/unsafe_refs.csv', 'wb') as csvfile:
    writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL)
    for line in out_lines:
        writer.writerow(line)

#Fix virtual function table references, created for macOS driver processing
#@author: Krzysztof '_0kami' Marciniak (F-Secure)
#@category Functions
from ghidra.app.cmd.data import CreateStructureCmd
from ghidra.program.model.data import CategoryPath
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.program.model.data import FunctionDefinitionDataType
from ghidra.program.model.data import StructureDataType
from ghidra.program.database.symbol import GhidraClassDB
from sys import exit

PointerDataType = getDataTypes('pointer')[0]
if not PointerDataType:
    print('[!] cannot find the pointer type, backing off...')
    exit(1)

classes = set()             # we want only unique ones
func = getFirstFunction()   # kick off the processing

# process all functions and retrieve their namespaces
# (AFAIK there is no other way to retrieve all namespaces)
while func:
    namespace = func.parentNamespace
    """
    In some cases the following condition will not be true.
    We will skip those.
    """
    if issubclass(namespace.getClass(), GhidraClassDB):
        # process only classes (to reconstruct vtables)
	classes.add(namespace)
    func = getFunctionAfter(func)

classes = list(classes)

ptr_size = currentProgram.getDefaultPointerSize()   # just in case
cutoff = 5000   # in case the cutoff condition doesn't work
alignment = 0xf # well, works for macOS drivers 

# the manager will be used to add new types
dtm = currentProgram.getDataTypeManager()
# let's leave it to Ghidra to resolve type conflicts
conflict_handler = DataTypeConflictHandler.DEFAULT_HANDLER

# print some debug/helper information
print("[+] vtable fixing start")
print("    ptr size  = {}".format(ptr_size))
print("    alignment = {}".format(hex(alignment)))
print("    cutoff    = {}".format(cutoff))
print("[+] classes to process: {}".format(len(classes)))

for cls in classes:
    # cls.toString() yields e.g. AppleBroadcomBluetoothHostController::MetaClass (GhidraClass)
    cname = cls.toString().split(' ')[0]
    print("[+] {} processing start".format(cname))

    types = getDataTypes(cname)
    if len(types) > 1 or not types:    # special case, e.g. metaclasses?
        print(
            "[!] {} has either no types or >1 ({}), skipping...".format(
                cname,
                len(types)
            )
        )
        continue

    ctype = types[0]    # the type, to which we want add vptr

    # add vptr only if there isn't one already
    if not ctype.numComponents:
        ctype.add(
            PointerDataType,
            ptr_size,
            "vptr",
            "Virtual function table pointer"
        )

    # fetch vtable symbols from the class
    symbols = getSymbols("vtable", cls)
    
    if not symbols:
        print("[!] no vtable for {}, skipping...".format(cname))
        continue
    
    # if there are indeed multiple symbols, use the first one
    vptr_sym = symbols[0]

    print(
        "[+] vptr for {} found @ 0x{}, looking for vtable...".format(
            cname,
            vptr_sym.address
        )
    )

    vtable_addr = vptr_sym.address.add(
        alignment + 1
    )	# one after the alignment
    print(
        "[+] vtable for {} found @ 0x{}, processing entries...".format(
            cname,
            vtable_addr
        )
    )
    cur_addr = vtable_addr

    # create the new datatype (Structure/class)
    vtable_type_name = "VTABLE_{}".format(cname)
    vtable_type = StructureDataType(
        vtable_type_name,
        0
    ) 

    cutoff_ctr = 0

    while cutoff_ctr < cutoff:
        data = getDataAt(cur_addr)
        
        if not data:
            cur_addr = cur_addr.add(ptr_size)
            continue

            print("[!] no data @ 0x{}, bailing out...".format(cur_addr))
            break	# no data at this address, skip

        if data.isPointer():    # it will (hopefully) be a function ptr
            func_ptr = getFunctionAt(data.value)

            if not func_ptr:    # weird stuff, just skip
                cur_addr = cur_addr.add(ptr_size)
                continue

            print(
                "[+] {} reference @ 0x{} ( -> 0x{}), adding to the vtable struct".format(
                    func_ptr.toString(),
                    cur_addr,
                    data.value
                )
            )

            func_name = func_ptr.toString() # include namespace

            # create a function definition
            func_definition = FunctionDefinitionDataType(
                CategoryPath.ROOT,
                func_name,
                func_ptr.getSignature()
            )
            dtm.addDataType(
                func_definition,
                conflict_handler
            )

            # add a function pointer to the structure
            vtable_type.add(
                func_definition,
                ptr_size,
                func_name,
                ""
            )
            cur_addr = cur_addr.add(ptr_size)
        cutoff_ctr += 1
    
    dtm.addDataType(
        vtable_type,
        conflict_handler
    )
    
    cmd = CreateStructureCmd(
        vtable_type,
        vtable_addr
    )
    success = cmd.applyTo(currentProgram)

    # pointer to the create data type
    vtable_ptr = dtm.getPointer(vtable_type)

    ctype.replaceAtOffset(
        0,
        vtable_ptr,
        ptr_size,
        "vptr",
        "Virtual function table pointer"
    )

    if not success:
        print("[!] could not apply the structure to given address")

    print("[+] {} processing finished".format(cname))

print("[+] all processing done")

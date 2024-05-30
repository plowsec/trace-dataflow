import pyvex
import archinfo

irsb = pyvex.lift(b"\x89\x44\x24\x48", 0x400400, archinfo.ArchAMD64())
# pretty-print the basic block
irsb.pp()

# this is the IR Expression of the jump target of the unconditional exit at the end of the basic block
print(irsb.next)

# this is the type of the unconditional exit (i.e., a call, ret, syscall, etc)
print(irsb.jumpkind)

# you can also pretty-print it
irsb.next.pp()

# iterate through each statement and print all the statements
for stmt in irsb.statements:
    stmt.pp()

# pretty-print the IR expression representing the data, and the *type* of that IR expression written by every store statement
import pyvex
for stmt in irsb.statements:
    if isinstance(stmt, pyvex.IRStmt.Store):
        print("Data:", end="")
        stmt.data.pp()
        print("")

        print("Type:", end="")
        print(stmt.data.result_type)
        print("")

# pretty-print the condition and jump target of every conditional exit from the basic block
for stmt in irsb.statements:
    if isinstance(stmt, pyvex.IRStmt.Exit):
        print("Condition:", end="")
        stmt.guard.pp()
        print("")

        print("Target:", end="")
        stmt.dst.pp()
        print("")

# these are the types of every temp in the IRSB
print(irsb.tyenv.types)

# here is one way to get the type of temp 0
print(irsb.tyenv.types[0])
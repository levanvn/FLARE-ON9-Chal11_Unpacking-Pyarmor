#import restrict_bypass, marshal
import marshal, dis
#from pytransform import pyarmor_runtime
#pyarmor_runtime()

a = marshal.loads(open("fixcode.marshal", "rb").read())
#print (dir(a))
print("co_varnames:		", a.co_varnames)
print("co_cellvars: 	", a.co_cellvars)
print("co_name: 		",	a.co_name)
print("co_names: 		",	a.co_names)
print("co_consts: 		",	a.co_consts)
print("co_filename: 	", a.co_filename)
print("co_freevars: 	",	a.co_freevars)
print("co_flags:		", hex(a.co_flags))
print("co_stacksize:		", hex(a.co_stacksize))

print("co_code:			", a.co_code)
b = bytearray(a.co_code)
#open("code", "wb").write(b)
print(type(a.co_name))
print("\nDisasm: ", dis.dis(a))
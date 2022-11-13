#Source: https://rushter.com/blog/python-bytecode-patch/
from types import CodeType
import marshal, dis
def fix_code(fn_code, payload):
	
	new_code_obj= CodeType(fn_code.co_argcount,
							 fn_code.co_kwonlyargcount,
							 fn_code.co_nlocals,
							 fn_code.co_stacksize,
							 fn_code.co_flags,
							 payload,
							 fn_code.co_consts,
							 fn_code.co_names,
							 fn_code.co_varnames,
							 fn_code.co_filename,
							 fn_code.co_name,
							 fn_code.co_firstlineno,
							 fn_code.co_lnotab,
							 fn_code.co_freevars,
							 fn_code.co_cellvars,
							 )
	return new_code_obj

code_obj = marshal.loads(open("code_obj.marshal2", "rb").read())
payload = code_obj.co_code 

opcode_dict = {91:156, 209:108, 233:90, 112:101, 172:160, 63:25, 208:161, 193:106, 200:105, 152:110, 46:4, 47:89, 215:107, 181:91, 39:83}
offset = 0xBC  #some unknown garbage code at the end of co_code
new_co_code = bytearray(len(payload))
print(payload)

for i in range(len(payload)):
	new_co_code[i] = payload[i]
	for x in opcode_dict:
		if i%2 == 0 and payload[i] == x:
			new_co_code[i] = opcode_dict[x]	
	if i%2 == 0 and payload[i] == 0:
		new_co_code[i] = 9
	if i >= offset and i %2 ==0 :
		new_co_code[i] = 9

print(new_co_code)

open("new_co_code", "wb").write(marshal.dumps(new_co_code))

new_code_obj = fix_code(code_obj, bytes(new_co_code))
#print("after : 	", new_code_obj.co_names)
open("fixcode.marshal", "wb").write(marshal.dumps(new_code_obj))		


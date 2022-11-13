import sys, marshal, ctypes
count = 0
for frame in sys._current_frames().values():	
	while frame.f_back != None: 

		code_obj = frame.f_code
		
		if count == 2: 			# frame where code object is stored
			print("Add of frame: ",hex(id(frame)))
			print("Add of code_obj: ",hex(id(code_obj)))
			print("Add of consts: ",hex(id(code_obj.co_consts)))
			#old_value = (*(code_obj.co_consts) - 0x7F38)^ current_time
			current_co_consts = ctypes.c_longlong.from_address(id(code_obj.co_consts)) 

			get_time = ctypes.c_longlong.from_address(0x000000006D709030) # adress of variable that store current_time
			old_value = ctypes.c_longlong((current_co_consts.value - ctypes.c_longlong(0x7F38).value) ^ get_time.value)
			print ("current_co_consts: ", hex(current_co_consts.value))
			print ("time_as_key: ", hex(get_time.value))
			print ("old_value: ", hex(old_value.value))
			ctypes.memmove(id(code_obj)+ 0x30, ctypes.byref(old_value), 8) # 0x30 is offset of co_consts in PyCodeObject

		open("code_obj.marshal" + str(count), "wb").write(marshal.dumps(code_obj))

		count += 1
		frame = frame.f_back 
	code_obj = frame.f_code
	break

open("code_obj.marshal" + str(count), "wb").write(marshal.dumps(code_obj))
open("co_code" + str(frame.f_lasti) + "_" + str(frame.f_lineno), "wb").write(marshal.dumps(code_obj.co_code))
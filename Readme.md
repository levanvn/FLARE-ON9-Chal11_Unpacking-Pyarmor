

# FLARE-ON 9- Challenge 11: Unpacking Pyarmor

FLARE-ON is an annual CTF event organized by Mandiant that focuses on malware and reverse engineering. Participating in challenges is an opportunity to help us access new ideas, and new techniques of malware, based on the experience of Mandiant experts.

In this year's challenges, challenge 8 and challenge 11 are all related to packing and obfuscating software. Challenge 8 is the most elaborately designed, and is considered the most difficult of the 11 challenges. We need to deobfuscate the .NET code to its original form and read the backdoor's flow to guess how the flag is generated. Both things need to be done meticulously and there are no shortcuts to getting the flag.

Challenge 11 is a python script protected with PyArmor in Advanced and restricted mode (Pyarmor is a well-known commercial software for protecting Python code). Flags can be easily obtained by "quick and dirty" by dumping process memory and checking for strings. But the more we dig into how to restore the original script, the more we discover how PyArmor and Python Internal work.

This write-up covers recovery from code that has been obfuscated by Pyarmor by advanced and restricted mode to the original code and also presents some explorations of how Pytransform works. [Pytransform](https://github.com/dashingsoft/pyarmor-core) is written in C which is the core library of Pyarmor. Because Pyarmor trial versions from 6.7.0 and later all use the core library pytransform r41.15, a detailed analysis of this version can help a lot of cases that we may encounter later.
## 1. Quick and Dirty way to get flag

Through reconnaissance by examining the strings, we see that the file is initially protected with Pyarmor, then packed with PyInstaller to convert to an 11.exe file. Reconnaissance also shows that python version is 3.7, pyarmor mode 2 advanced is used.

One way to recon a python file is to press Ctrl+C/ Ctrl+Z to check the stack status.

[![first](https://user-images.githubusercontent.com/39437600/201511866-27f8b130-4c35-4ab7-8293-b22472b6dfb9.png)](https://user-images.githubusercontent.com/39437600/201511866-27f8b130-4c35-4ab7-8293-b22472b6dfb9.png)

Figure 1. Print Traceback

Dump process memory with a tool like process hacker, we see strings containing flags, url

[![2](https://user-images.githubusercontent.com/39437600/201511891-b0fe8d71-09f9-4ee5-a161-2414704b9216.png)](https://user-images.githubusercontent.com/39437600/201511891-b0fe8d71-09f9-4ee5-a161-2414704b9216.png)

Figure 2. Check process strings

A pretty cool technique used in write-ups by [Mandiant](https://www.mandiant.com/sites/default/files/2022-11/11-flareon9-solution.pdf) and some other authors is the hooking library. Python files often import other modules, we can create a new file with the same name to dump the variables and arguments passed into the new module.

[![3](https://user-images.githubusercontent.com/39437600/201511923-94052b32-7f3e-45fa-a914-b09e37d7476f.png)](https://user-images.githubusercontent.com/39437600/201511923-94052b32-7f3e-45fa-a914-b09e37d7476f.png)

Figure 3. Hijacking library to dump arguments – Source: Mandian

## [](https://github.com/levanvn/FLARE-ON9-Chal11_Unpacking-Pyarmor/edit/main/README.md#2-reverse-engineering-pytransfrom)2. Reverse Engineering Pytransfrom

The following section explains some basic concepts about Python Objects, which we can learn more about in the Python Internal documentation. These constructs are all defined in [CPython](https://github.com/python/cpython) .

**PyObject** : This is the base object in python, all objects in python can refer to PyObject. PyObject contains 2 fields ob_refcnt and ob_type. ob_refcnt stores the number of references to an object, used in memory management. ob_type points to a PyTypeObject struct indicating the type of Object. For example, PyTuple_Type indicates that the object is a tuple, PyCode_Type indicates that the object is a Code object, etc.

**PyCodeObject** : Contains executable code (bytecode). The compiled python source code will be saved as a Code Object (eg .pyc file), the code object containing the bytecode will be interpreted by the python virtual machine (ex. python37.dll in windows). PyCodeObject contains several important fields:

-   co_code: contains python bytecode
    
-   co_consts: tuple containing constants used by bytecode
    
-   co_names: tuple stores names such as function names, import modules, etc.
    
-   co_flags: bitmap stores the properties of the code object, Pyarmor uses unused bits to mark Pyarmor modes
    

[![4](https://user-images.githubusercontent.com/39437600/201512001-f9f21dec-35b2-4751-91dc-8384b087ad28.png)](https://user-images.githubusercontent.com/39437600/201512001-f9f21dec-35b2-4751-91dc-8384b087ad28.png)

Figure 4. An example of a code object

In python37 each command consists of 2 bytes in bytecode. The first byte is the opcode, the second byte is the argument used for that opcode. For example, the first 2 bytecode bytes in the co_code field of the code object in the image above are 0x74, 0x0E. 0x74 is the opcode of LOAD_GLOBAL, argument 0x0E indicates the index in the field co_names[0xe] = _armor_wrap_ . This command will push a PyObject named _armor_wrap_ onto the stack. The next 2 bytes are 0x83, 0x00 corresponds to the opcode CALL_FUNCTION and the argument 0x00 indicates that this function has no arguments, the address of the function is at the top-of-stack (TOS) is the _armor_wrap_ function loaded by LOAD_GLOBAL above.

Python37 has about 120 opcodes defined at [opcode.h](https://github.com/python/cpython/blob/main/Include/opcode.h) in CPython

**PyFrameObject:** Similar in concept to Stack Frame in C, Frame Object holds the context of Code Object when executing. The f_code field points to the code object of that frame, the f_back field points to the previous frame. Python provides inspect.currentframe() or sys._current_frames() function to get current frame, we can browse all previous frames thanks to f_back field. When Ctrl+Z/ Ctrl+C is pressed, python will print the traceback according to the current frames.

Before diving into reverse engineering we should read Pyarmor's [documentation](https://pyarmor.readthedocs.io/en/latest/how-to-do.html#), which explains the features, and how pyarmor protects code objects. It does not provide details on how Pyarmor is implemented but gives us an idea of ​​how Pyarmor works.

The process of obfuscating a code object starts from the inside out. First, the bytecode in the co_code field will be messed up. To do this Pyarmor will change the default opcodes of Python, and define new opcodes. For example, python opcode 0x6C (108) IMPORT_NAME would correspond to 0xD1 (209) in Pyarmor. To deobfuscate we need to map the corresponding opcodes. There are about 120 opcodes, pytransfom versions can change the mapping continuously, however, Pyarmor trial versions from 6.7.0 all use pytransform r41.15. After messing the opcodes, the new bytecode continues to be encrypted with the secret key. Related changes include adding wrap function name to co_consts, increasing co_stacksize, and setting the CO_OBFUSCATED bit to co_flags. Here the bytecode has been messed up and encrypted, however, the strings in co_consts, co_names,... are still not obfuscated. The current code object is called **string_code**. Pyarmor uses the marshal module to serialize code objects and implements encryption algorithms to convert string_code to obfuscated_code.

[![5](https://user-images.githubusercontent.com/39437600/201512024-77f33ce6-a40d-4dd6-852a-38ab34474ff2.png)](https://user-images.githubusercontent.com/39437600/201512024-77f33ce6-a40d-4dd6-852a-38ab34474ff2.png)

Figure 5. Obfuscate string_object in Pyarmor documentation

During run time, pyarmor will decrypt obfuscated_code by the corresponding algorithm to convert it to string_code. In python, bytecode execution handling is implemented in the PyEval_EvalFrameDefault function in [ceval.c](https://github.com/python/cpython/blob/main/Python/ceval.c) in the CPython source code, Pyarmor has modified this function with self-define opcodes, in addition, some important changes such as frame.f_code will point to a NULL structure, so if we traverse frames to dump the code object will return empty results, f_code.co_consts is also changed and restored only when needed in the LOAD_CONST opcode

[![6](https://user-images.githubusercontent.com/39437600/201512030-2d362646-2083-4ff7-a5b8-cda55e7f30d5.png)](https://user-images.githubusercontent.com/39437600/201512030-2d362646-2083-4ff7-a5b8-cda55e7f30d5.png)

Figure 6. Restore original co_consts in LOAD_CONST opcode


When we debug pytransform.dll or patch binary, the program will crash. On [the documentation](https://pyarmor.readthedocs.io/en/latest/security.html) of Pyarmor also introduces pytransform's Self-Protection and Cross-Protection features. Obfuscated code is protected by pytransform, pytransform protects itself by JIT (just-in-time) technique, and Obfuscated script checks the integrity of pytransform before executing. JIT techniques include code segment checksum, anti-debug, check tickcount, and check hardware breakpoint. Not all modes have these security features, in advanced and restricted modes like in this challenge we encounter the above features. To bypass we can use plugins like ScyllaHide in x64dbg or set 0xEBFE to perform debugging or stop at the desired location.

Existing pyarmor unpacking methods are all dynamic because it's hard to get the key to decrypt the obfuscated_code to string_code and the key to decrypt bytecode just by static analysis. We need to run the executable, stopping at the desired location to dump to the string_code. From string_code, we continue to decode the bytecode then change the pyarmor opcodes to the corresponding python opcode to recover the original bytecode.

## [](https://github.com/levanvn/FLARE-ON9-Chal11_Unpacking-Pyarmor/edit/main/README.md#3-unpacking)3. Unpacking


With the above information, we now proceed to unpack to restore the original script.

First, we need to get the string_code. After that restore the bytecode in the code object

### 3.1 Dumping string_code

When running the Obfuscated script, pyarmor will decrypt the obfuscated_code to obtain the string_code and execute this string_code. Because Pyarmor recursively obfuscates the modules imported in the main module, if the Code Object is the main module, the string_code will be executed by the PyEval_EvalCode function, otherwise, if the code object is an import module, the string_code will be executed by the PyImport_ExecCodeModuleEx function

[![7](https://user-images.githubusercontent.com/39437600/201512050-2e7a5b8d-eaa2-4523-b6e6-4e611083e2dc.png)](https://user-images.githubusercontent.com/39437600/201512050-2e7a5b8d-eaa2-4523-b6e6-4e611083e2dc.png)

Figure 7. Exceute string_code by CPython API in Pytransform.dll

So to dump the string_code of the main module we need to set a breakpoint at the location where PyEval_EvalCode will be called (at 0x6D605827). At this location, we will traverse all the frames, and dump the code object of the frame where the string_code of the main module is located. To inject python code into python process, we can use [PyInjector](https://github.com/call-042PE/PyInjector) , Pyinjector.dll will inject python code in code.py using PyRun_SimpleString API: [

![7 5](https://user-images.githubusercontent.com/39437600/201512054-3a927249-b32b-4498-8ec0-23df63c573f4.png)](https://user-images.githubusercontent.com/39437600/201512054-3a927249-b32b-4498-8ec0-23df63c573f4.png)

After dumping the code object at PyEval_EvalCode , checking the properties of the code object, we see that co_consts already contains strings (including flag)

[![8](https://user-images.githubusercontent.com/39437600/201512062-9f76bd6a-5db7-42fd-86c5-9175e2977165.png)](https://user-images.githubusercontent.com/39437600/201512062-9f76bd6a-5db7-42fd-86c5-9175e2977165.png)

Figure 8. Code object of pyarmor function

We note that the argument passed to the PyEval_EvalCode function is the code object containing our string_code.

However, the bytecode is still being encrypted and has not been decoded yet. Also at this point, the new Frame hasn't been created yet so we can't dump the code object by traversing the frames. The python Marshal module also does not support the dump object method with an address as an argument. So we need to find a breakpoint where the bytecode has been decrypted and a new frame has been created so that we can dump the code object.

### 3.2 Restore original bytecode

In the self-implemented PyEval_EvalFrameDefault function, Pytransform has pointed frame.f_code to an empty structure, so if we set the breakpoint at this position, we only get an empty code object. The appropriate breakpoint location is right where Pytransform calls PyEval_EvalFrameDefault (0x06D604883) to handle the opcodes.

Note that after restoring string_code, pyarmor will point the co_consts field to a different value than the original, the original value will be recalculated only when used by LOAD_CONST. The new value of co_consts will be calculated by new_value = (old_value - 0x7F38) ^ current_time. So to get the original co_consts value we need to recalculate the old_value in the code.py file:

[![9](https://user-images.githubusercontent.com/39437600/201512068-1132730c-2dd8-4850-8b12-f01370804bd7.png)](https://user-images.githubusercontent.com/39437600/201512068-1132730c-2dd8-4850-8b12-f01370804bd7.png)

Figure 9. Python Code to restore original co_consts

At this point, the co_names, co_consts fields of the code object are clear, but the opcodes in the co_code are still not properly mapped to the standard form:

[![ten](https://user-images.githubusercontent.com/39437600/201512075-0dd583ca-d8ba-45e0-be9d-8accfbe25061.png)](https://user-images.githubusercontent.com/39437600/201512075-0dd583ca-d8ba-45e0-be9d-8accfbe25061.png)

Figure 10. Code object with obfuscated co_code

We have about 120 opcodes to check, here only check some of the opcodes included in the co_code above.

The following table maps between the opcode defined in CPython and the opcode in Pytransform and the corresponding name:

[![11](https://user-images.githubusercontent.com/39437600/201512097-450152ef-dc22-4809-a5b8-d6f26c1c0af1.png)](https://user-images.githubusercontent.com/39437600/201512097-450152ef-dc22-4809-a5b8-d6f26c1c0af1.png)

Figure 11. Python37 - Pytransform opcode mapping

To change the co_code of the code object we can use CodeType and convert the opcodes from pytransform to standard Python form.

[![twelfth](https://user-images.githubusercontent.com/39437600/201512125-2e66b600-b66c-4195-a687-0c9a8e0f718a.png)](https://user-images.githubusercontent.com/39437600/201512125-2e66b600-b66c-4195-a687-0c9a8e0f718a.png)

Figure 12. Fix pyarmor opcode to Python standard opcode

After replacing we have the result:

[![13](https://user-images.githubusercontent.com/39437600/201512133-de6b0a85-4920-4769-a722-b0c6afb9dfb9.png)](https://user-images.githubusercontent.com/39437600/201512133-de6b0a85-4920-4769-a722-b0c6afb9dfb9.png)

Figure 13. Bytecode after deobfuscating

From the opcode above, we can convert to Python source code as follows:

![14](https://user-images.githubusercontent.com/39437600/201516571-e7688578-6e36-40c2-aeaa-5e928d0a627d.PNG)

Figure 14. Original Python code


## References

 1. https://www.mandiant.com/sites/default/files/2022-11/11-flareon9-solution.pdf
 2. https://0xdf.gitlab.io/flare-on-2022/challenge_that_shall_not_be_named#
 3. https://github.com/binref/refinery/blob/master/tutorials/tbr-files.v0x05.flare.on.9.ipynb
 4. https://www.elastic.co/flare-on-9-solutions-burning-down-the-house
 5. https://github.com/Svenskithesource/PyArmor-Unpacker
 6. https://github.com/call-042PE/PyInjector
 7. https://pyarmor.readthedocs.io/en/latest/how-to-do.html
 8. https://rushter.com/blog/python-bytecode-patch/
"# FLARE-ON9-Chal11_Unpacking-Pyarmor" 

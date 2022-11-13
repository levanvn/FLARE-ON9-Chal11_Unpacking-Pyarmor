# FLARE-ON 9- Challenge 11:  Unpacking Pyarmor

FLARE-ON là sự kiện  CTF hằng năm được tổ chức bởi Mandiant tập trung vào lĩnh vực phần mềm độc hại và dịch ngược phần mềm. Tham gia giải quyết các challenges là dịp giúp chúng ta tiếp cận các ý tưởng mới, các kỹ thuật mới của phần mềm độc hại, dựa trên chính kinh nghiệm thực tế của các chuyên gia Mandiant.

Trong các challenges năm nay, challenge 8 và challenge 11 đều liên quan đến việc packing, obfuscating. Challenge 8 được thiết kế tỉ mỉ nhất, và được đánh giá là khó nhất trong 11 challenges. Chúng ta cần deobfuscate .NET code về dạng mã nguồn ban đầu, đọc hiểu luồng hoạt động của backdoor để đoán cách flag được sinh ra. Cả 2 việc đều cần làm tỉ mỉ và không có đường tắt để lấy flag.

Challenge 11 là một script python được bảo vệ bằng PyArmor ở chế độ advanced và restricted (Pyarmor là phần mềm thương mại nổi tiếng để bảo vệ code Python).  Flag có thể lấy dễ dàng bằng cách khá “quick and dirty” là dump process memory và kiểm tra các strings. Nhưng càng đi sâu tìm cách khôi phục được script ban đầu, chúng ta càng khám phá nhiều hơn về cách hoạt động của PyArmor và Python Internal.

Bài write-up này trình bày quá trình khôi phục từ mã đã bị obfuscated bởi Pyarmor ở mode advanced và restricted về dạng mã original, qua đó cũng trình bày một số khám phá trong cách hoạt động của Pytransform. [Pytransform](https://github.com/dashingsoft/pyarmor-core) được viết bằng C là thư viện lõi của Pyarmor. Bởi vì các phiên bản Pyarmor trial từ 6.7.0 trở về sau đều  sử dụng core library pytransform r41.15, việc phân tích chi tiết về phiên bản này có thể giúp rất nhiều trường hợp mà chúng ta có thể gặp sau này.

## 1.Quick and Dirty way to get flag

Qua quá trình reconnaissance bằng việc kiểm tra các strings, ta thấy rằng  file ban đầu được bảo vệ bằng Pyarmor, sau đó được đóng gói bằng PyInstaller để chuyển sang file 11.exe. Quá trình reconnaissance cũng cho thấy phiên bản python là 3.7, pyarmor mode 2 advanced được sử dụng.

Một cách để recon đối với file python là nhân Ctrl+C, Ctrl+Z để kiểm tra trạng thái stack.

![1](https://user-images.githubusercontent.com/39437600/201511866-27f8b130-4c35-4ab7-8293-b22472b6dfb9.png)


Figure 1. Print Traceback

Dump process memory bằng công cụ như process hacker ta thấy các string có chứa flag, url 

![2](https://user-images.githubusercontent.com/39437600/201511891-b0fe8d71-09f9-4ee5-a161-2414704b9216.png)

Figure 2. Check process strings

Một kỹ thuật khá hay được sử dụng trong write-up của [Mandiant](https://www.mandiant.com/sites/default/files/2022-11/11-flareon9-solution.pdf) và một số tác giả khác là hooking library. Các file python thường import các module khác, chúng ta có thể tạo ra file mới có cùng tên để dump các biến, các đối số truyền vào module mới

![3](https://user-images.githubusercontent.com/39437600/201511923-94052b32-7f3e-45fa-a914-b09e37d7476f.png)

 Figure 3. Hijacking library to dump arguments – Source: Mandian

## 2. Reverse Engineering Pytransfrom

Phần sau đây giải thích một số khái niện cơ bản về Python Object, chúng ta có thể tìm hiểu chi tiết hơn ở các tài liệu về Python Internal. Các cấu trúc này đều được định nghĩa ở [CPython](https://github.com/python/cpython).

**PyObject**:  Đây là object cơ sở trong python, tất cả các object trong python đều có thể quy chiếu về PyObject. PyObject chứa 2 trường là  ob_refcnt và ob_type. ob_refcnt lưu số lượng reference đến một object, được dùng trong memory management. ob_type trỏ đến một PyTypeObject struct cho biết type của Object. Ví dụ PyTuple_Type cho biết object là một tuple, PyCode_Type cho biết object là Code object,..

**PyCodeObject**: Chứa mã thực thi (bytecode). Mã nguồn python khi biên dịch sẽ được lưu ở dạng Code Object ( ví dụ .pyc file),code object chứa các bytecode sẽ được thông dịch nhờ máy ảo python ( ex. python37.dll trong windows). PyCodeObject chứa một số trường quan trọng:

- co_code: chứa python bytecode

- co_consts: tuple chứa các constants được sử dụng bởi bytecode

- co_names: tuple lưu các names như tên của các function, import module,…

- co_flags: bitmap lưu các thuộc tính của code object, Pyarmor sử dụng các các bit chưa dùng đến để đánh dấu các mode của Pyarmor

![4](https://user-images.githubusercontent.com/39437600/201512001-f9f21dec-35b2-4751-91dc-8384b087ad28.png)

Figure 4. An example of a code object 

Ở python37 mỗi command bao gồm 2 byte trong bytecode. Byte đầu tiên là opcode, byte thứ hai là đối số dùng cho opcode đó. Ví dụ 2 bytes bytecode đầu tiên trong trường co_code của code object ở hình trên là 0x74, 0x0E. 0x74 là opcode của LOAD_GLOBAL, đối số 0x0E cho biết index trong trường co_names[0xe] = _armor_wrap_. Lệnh này sẽ push một PyObject có tên _armor_wrap_ vào stack. 2 byte tiếp theo là 0x83, 0x00 tương ứng với opcode CALL_FUNCTION và đối số 0x00 chỉ ra rằng function này không có đối số truyền vào, địa chỉ của fucntion nằm ở top-of-stack (TOS) là hàm _armor_wrap_ được load bởi LOAD_GLOBAL ở trên.

Python37 có khoảng 120 opcode được định nghĩa ở [opcode.h](https://github.com/python/cpython/blob/main/Include/opcode.h) trong CPython

**PyFrameObject:** Khái niệm tương tự Stack Frame trong C, Frame Object lưu giữ context của Code Object khi thực thi. Trường f_code trỏ về code object của frame đó, trường f_back trỏ về Frame trước đó. Python cung cấp hàm inspect.currentframe() hoặc sys._current_frames() để lấy Frame hiện tại, chúng ta có thể duyệt tất cả các frame trước đó nhờ trường f_back. Khi nhấn Ctrl+Z/ Ctrl+C, python sẽ in traceback theo các frame hiện thời.

Trước khi đi vào reverse engineering chúng ta nên đọc documentation của Pyarmor, bao gồm giải thích các tính năng, và cách thức mà pyarmor bảo vệ code object. Nó không cung cấp chi tiết về cách Pyarmor được implement, nhưng cung cấp cho chúng ta các ý tưởng về cách hoạt động của Pyarmor.

Quá trình obfuscate một code object bắt đầu từ trong ra ngoài. Đầu tiên bytecode trong trường co_code sẽ được làm làm rối. Để làm điều này Pyarmor sẽ thay đổi các opcode mặc định của Python, define các opcode mới. Ví dụ opcode 0x6C (108) IMPORT_NAME của python sẽ tương ứng với 0xD1 (209) trong Pyarmor. Để deobfucate ta cần ánh xạ các opcode tương ứng. Có khoảng 120 opcode, các phiên bản pytransfom có thể liên tục thay đổi cách ánh xạ, tuy nhiên các phiên bản dùng thử Pyarmor từ 6.7.0 đều  dùng pytransform r41.15. Sau khi làm rối các opcode, bytecode mới tiếp tục được mã hóa bằng secret ket .Các thay đổi liên quan bao gồm thêm wrap function name vào co_consts, increase co_stacksize, set bit CO_OBFUSCATED vào co_flags. Đến đây phần bytecode đã được làm rối và mã hóa, tuy nhiên các strings trong co_consts, conames,... vẫn chưa bị obfuscate. Code object hiện thời tạm gọi là **string_code**. Pyarmor sử dụng marshal module để serialization code object và thực hiện các thuật toán mã hóa để chuyển string_code về dạng obfuscated_code

![5](https://user-images.githubusercontent.com/39437600/201512024-77f33ce6-a40d-4dd6-852a-38ab34474ff2.png)

Figure 5. Obfuscate string_object in Pyarmor documentation

Trong quá trình run time, pyarmor sẽ giải mã obfuscated_code bằng thuật toán tương ứng để chuyển về string_code. Trong python, việc thực thi các bytecode được implemented ở hàm **PyEval_EvalFrameDefault** trong [ceval.c](https://github.com/python/cpython/blob/main/Python/ceval.c) trong mã nguồn CPython, Pyarmor đã chỉnh sửa hàm này bằng các self-define opcode, ngoài ra một số thay đổi quan trọng như frame.f_code sẽ trỏ đến một cấu trúc NULL, do đó nếu chúng ta duyệt các frame để dump code object sẽ trả về các kết quả rỗng, f_code.co_consts cũng được thay đổi và chỉ được khôi phục khi cần bởi opcode LOAD_CONST

![6](https://user-images.githubusercontent.com/39437600/201512030-2d362646-2083-4ff7-a5b8-cda55e7f30d5.png)

Figure 6. Restore original co_consts in LOAD_CONST opcode

Khi chúng ta debug pytransform.dll hoặc patch binary, chương trình sẽ bị crash. Trên [documentation](https://pyarmor.readthedocs.io/en/latest/security.html) của Pyarmor cũng giới thiệu về tính năng Self-Protection và Cross-Protection của pytransform. Obfuscated code được bảo về bằng pytransform, pytransform tự bảo vệ chính nó bằng JIT ( just-in-time) technique, Obfuscated script kiểm tra toàn vẹn của pytransform trước khi thực thi. Các kỹ thuật bao gồm kiểm tra checksum của code segment, anti-debug, check tickcount, check hardware breakpoint. Không phải tất cả các mode đều có các security feature này, ở mode advanced và retricted như trong challenge, chúng ta gặp phải các tính năng trên. Để bypass chúng ta có thể sử dụng các plugin như ScyllaHide trong x64dbg hoặc đặt 0xEBFE để thực hiện debug hoặc dừng tại vị trí mong muốn.

Các phương pháp unpacking pyarmor hiện tại đều theo phương pháp dynamic, vì thật khó để lấy được key giải mã obfuscated_code về string_code và key để giải mã bytecode chỉ bằng việc static analysis. Chúng ta cần run file thực thi, dừng ở vị trí mong muốn để dump xuống string_code. Từ string_code, chúng ta tiếp tục giải mã bytecode sau đó thay đổi các opcode của pyarmor thành opcode của python tương ứng để khôi phục bytecode ban đầu.

## 3. Unpacking

Với các thông tin ở trên bây giờ chúng ta tiến hành unpacking để khôi phục được script gốc.

Đầu tiên chúng ta cần lấy được string_code. Sau đó khôi phục bytecode trong code object

### 3.1 Dumping string_code

Khi run Obfuscated script, pyarmor sẽ giải mã obfuscated_code để thu được string_code và thực thi string_code này. Bởi vì Pyarmor sẽ obfuscate đệ quy các module được import trong main module, nếu Codo Object là main module, string_code sẽ được thực thi bởi hàm PyEval_EvalCode, ngược lại nếu code object là import module, string_code sẽ được thực thi bởi hàm PyImport_ExecCodeModuleEx

![7](https://user-images.githubusercontent.com/39437600/201512050-2e7a5b8d-eaa2-4523-b6e6-4e611083e2dc.png)

Figure 7. Exceute string_code by CPython API in Pytransform.dll

Như vậy để dump được string_code của main module ta cần đặt điểm dừng tại vị trí mà PyEval_EvalCode sẽ được gọi (breakpoint tại 0x6D605827). Tại vị trí này chúng ta sẽ duyệt tất cả các frame, dump code object của frame nơi có chứa string_code của main module . Để inject python code vào python process, ta có thể dùng [PyInjector](https://github.com/call-042PE/PyInjector), Pyinjector.dll sẽ inject python code trong code.py bằng API PyRun_SimpleString:
![7 5](https://user-images.githubusercontent.com/39437600/201512054-3a927249-b32b-4498-8ec0-23df63c573f4.png)

Sau khi dump code object tại PyEval_EvalCode , kiểm tra các thuộc tính của code object, ta thấy trong co_consts đã chứa các strings ( bao gồm cả flag)

![8](https://user-images.githubusercontent.com/39437600/201512062-9f76bd6a-5db7-42fd-86c5-9175e2977165.png)

Figure 8. Code object of __pyarmor__ function

Chúng ta lưu ý là đối số truyền vào hàm PyEval_EvalCode là code object chứa string_code của chúng ta.

Tuy nhiên phần bytecode vẫn đang bị mã hóa và vẫn chưa được giải mã. Ngoài ra tại thời điểm này Frame mới vẫn chưa được tạo cho nên chúng ta không thể dump code object bằng cách duyệt các frame. Module Marshal của python cũng không hỗ trợ phương thức dump object với đối số truyền vào là một address. Do đó chúng ta cần tìm một điểm dừng mà tại đó bytecode đã được giải mã và frame mới đã được tạo để có thể dump code object.

### 3.2 Restore original bytecode

Trong hàm **PyEval_EvalFrameDefault** Pytransform đã trỏ frame.f_code đến một cấu trúc rỗng, do đó nếu ta đặt breakpoint tại vị trí này thì chỉ thu được một code object rỗng. Vị trí đặt breakpoint thích hợp là ngay tại vị trí mà Pytransform gọi **PyEval_EvalFrameDefault** (0x06D604883) để thực thi các opcode.

Lưu ý là sau khi restore string_code, pyarmor sẽ trỏ trường co_consts đến một giá trị khác so với ban đầu, giá trị ban đầu sẽ được tính lại chỉ khi được dùng đến bởi LOAD_CONST. Giá trị mới của co_consts sẽ được tính bằng cách new_value = (old_value - 0x7F38) ^ current_time. Do đó để lấy giá trị co_consts ban đầu chúng ta cần tính lại old_value trong file code.py:

![9](https://user-images.githubusercontent.com/39437600/201512068-1132730c-2dd8-4850-8b12-f01370804bd7.png)

Figure 9. Python Code to restore original co_consts

Đến đây các trường co_names, co_consts của code object đã rõ ràng, tuy nhiên các opcode trong co_code vẫn chưa được ánh xạ đúng về dạng chuẩn:

![10](https://user-images.githubusercontent.com/39437600/201512075-0dd583ca-d8ba-45e0-be9d-8accfbe25061.png)

Figure 10. Code object with obfuscated co_code

Chúng ta có khoảng 120 opcode cần kiểm tra, ở đây chỉ kiểm tra một số opcode có trong co_code ở trên

Bảng sau ánh xạ giữa opcode được define trong CPython và opcode trong Pytransform và name tương ứng:


![11](https://user-images.githubusercontent.com/39437600/201512097-450152ef-dc22-4809-a5b8-d6f26c1c0af1.png)

Figure 11. Python37 - Pytransform opcode mapping

Để thay đổi co_code của code object ta có thể dùng CodeType và chuyển các opcode từ pytransform sang dạng chuẩn của Python

![12](https://user-images.githubusercontent.com/39437600/201512125-2e66b600-b66c-4195-a687-0c9a8e0f718a.png)

Figure 12. Fix pyarmor opcode to Python standard opcode

Sau khi thay thế chúng ta có kết quả:

![13](https://user-images.githubusercontent.com/39437600/201512133-de6b0a85-4920-4769-a722-b0c6afb9dfb9.png)

Figure 13. Bytecode after deobfuscating

Từ opcode ở trên ta có thể chuyển về dạng mã nguồn Python như sau:

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

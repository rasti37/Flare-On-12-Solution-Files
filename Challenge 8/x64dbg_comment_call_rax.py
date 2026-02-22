import time
from x64dbg import *
from iced_x86 import Decoder, Formatter, FormatterSyntax

BASE_IMAGE = 0x140000000
BIN_DATA = open("FlareAuthenticator.exe", "rb").read()
formatter = Formatter(FormatterSyntax.NASM)

def read_instruction_bytes(start, end):
    sz = end - start
    return Memory.Read(start, sz+1)

# find all "jmp rax" and return the address of the exact next instructions
# to put a breakpoint in x64dbg
# also return address of last function's instruction
def dump_call_rax_addresses(function_code):
    decoder = Decoder(64, function_code, ip=OEP)

    end = None
    breakpoint_addresses = []
    for instr in decoder:
        disasm = formatter.format(instr)
        if 'call rax' in disasm:
            breakpoint_addresses.append(instr.ip)
        # start_index = instr.ip - OEP
        # bytes_str = function_code[start_index:start_index + instr.len].hex().upper()
        # print(f"{instr.ip:016X} {bytes_str:20} {disasm}")
        if 'ret' in disasm:
            break
    return breakpoint_addresses

# ------------------------------------------------------------------- #

OEP = 0x140012E50

# ------------------------------------------------------------------- #

FUNCTION_RAW_ADDRESS = OEP - BASE_IMAGE - 0x1000 + 0x400
function_code = BIN_DATA[FUNCTION_RAW_ADDRESS:]

breakpoint_addresses = dump_call_rax_addresses(function_code)

# set breakpoint at all "jmp rax" instructions
for bp in breakpoint_addresses:
    Debug.SetBreakpoint(bp)

current_address = OEP

visited = []
ignore_list = eval(open("ignores.txt").read())
while Register.GetRIP() != breakpoint_addresses[-1]:
    Debug.Run()

    current_address = Register.GetRIP()
    istart, iend = Gui.Disassembly.SelectionGet()
    code = read_instruction_bytes(istart, iend)
    if code == b"\xff\xd0":
        jmp_addr = Register.GetRAX()
        if jmp_addr not in ignore_list:
            label = Label.Get(jmp_addr)
            if not label:
                label = hex(jmp_addr)
            print(f'{current_address = :x} calls to {label}')
            Comment.Set(istart, f'Calls {label}', True)
    time.sleep(0.3)

Debug.Pause()

for bp in breakpoint_addresses:
    Debug.DeleteBreakpoint(bp)

open(f"patched_jmp_rax_{hex(OEP)}.txt", "w").write(str(patched_jmp_rax))
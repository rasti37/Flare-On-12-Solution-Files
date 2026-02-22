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
def dump_jmp_rax_addresses(function_code):
    decoder = Decoder(64, function_code, ip=OEP)

    end = None
    breakpoint_addresses = []
    for instr in decoder:
        disasm = formatter.format(instr)
        if 'jmp rax' in disasm:
            breakpoint_addresses.append(instr.ip)
        # start_index = instr.ip - OEP
        # bytes_str = function_code[start_index:start_index + instr.len].hex().upper()
        # print(f"{instr.ip:016X} {bytes_str:20} {disasm}")
        if 'ret' in disasm:
            break
    return breakpoint_addresses

# ------------------------------------------------------------------- #

OEP = 0x140081760

# ------------------------------------------------------------------- #

FUNCTION_RAW_ADDRESS = OEP - BASE_IMAGE - 0x1000 + 0x400
function_code = BIN_DATA[FUNCTION_RAW_ADDRESS:]

breakpoint_addresses = dump_jmp_rax_addresses(function_code)

breakpoint_addresses.append(breakpoint_addresses[-1]+2)

# set breakpoint at all "jmp rax" instructions
for bp in breakpoint_addresses:
    Debug.SetBreakpoint(bp)

current_address = OEP

patched_jmp_rax = []
while Register.GetRIP() != breakpoint_addresses[-1]:
    Debug.Run()

    current_address = Register.GetRIP()
    istart, iend = Gui.Disassembly.SelectionGet()
    code = read_instruction_bytes(istart, iend)
    if current_address in patched_jmp_rax:
        jmp_addr = Register.GetRAX()
        if abs(jmp_addr - current_address) != 2:
            # print(f'reverting patch @ 0x{current_address:x} because next jmp = {jmp_addr}')
            patched_jmp_rax.remove(current_address)
            # if at some point, jmp rax is conditional
            # patch it back, else infinite loop
            Assembler.AssembleMemEx(current_address, "jmp rax", True)
            # reset breakpoint at jump rax
            Debug.SetBreakpoint(current_address)
    else:
        # check if code == "jmp rax"
        if code == b"\xff\xe0":
            jmp_addr = Register.GetRAX()
            if abs(jmp_addr - current_address) == 2:
                patched_jmp_rax.append(current_address)
                # print(f'patching @ 0x{current_address:x} because next jmp = ip + 2')
                # patch jmp rax to nop
                Assembler.AssembleMemEx(current_address, "nop", True)
                # delete breakpoint at "nop"
                Debug.DeleteBreakpoint(bp)
    time.sleep(0.3)

    if current_address == breakpoint_addresses[-2]:
        Debug.StepOver()
        Debug.StepOver()

Debug.Pause()

for bp in breakpoint_addresses:
    Debug.DeleteBreakpoint(bp)

open(f"patched_jmp_rax_{hex(OEP)}.txt", "w").write(str(patched_jmp_rax))
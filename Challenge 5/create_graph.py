from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def get_insn_size(addr):
    return DecodeInstruction(addr).size

def get_mnemonic(addr):
    sz = ida_ua.decode_insn(ida_ua.insn_t(), addr)
    code = ida_bytes.get_bytes(addr, sz)
    return next(md.disasm(code, addr)).mnemonic

def check_opcode(addr):
    return get_bytes(addr, 1)

def fetch_jmp_address(addr):
    return get_operand_value(addr, 0)

def get_next_state(addr):
    jmp_address = fetch_jmp_address(addr)
    transistions_updated = False
    new_state = None
    while get_mnemonic(jmp_address) != 'jmp':
        size = ida_ua.decode_insn(ida_ua.insn_t(), jmp_address)
        insn_bytes = ida_bytes.get_bytes(jmp_address, size)

        # check if transition updated
        if get_mnemonic(jmp_address) == 'inc':
            transistions_updated = True

        if insn_bytes.startswith(bytes.fromhex('48 C7 84 24 30 8D 05 00')):
            # mov [rsp+offset], XXXX
            # we found mov instruction that sets next state
            new_state = int.from_bytes(insn_bytes[-4:], 'little')
            assert 0 <= new_state <= ncases, f'error while parsing state update  @ 0x{addr:x}'
        jmp_address += size

    if transistions_updated and new_state:
        return new_state
    else:
        return None

md = Cs(CS_ARCH_X86, CS_MODE_64)
ncases = 90780
cases = eval(open('cases.txt').read())

GRAPH = {}
for idx, case in enumerate(cases):
    addr = case
    GRAPH[idx] = []
    while get_mnemonic(addr) != 'jmp':
        sz = get_insn_size(addr)
        # found right cmp
        if get_mnemonic(addr) == 'cmp':
            insn_bytes = ida_bytes.get_bytes(addr, sz)
            if sz == 8 or insn_bytes.startswith(bytes.fromhex('80 7C 24')):
                operand = get_operand_value(addr, 1)
                assert 0x20 <= operand <= 0x7e
                ch = chr(operand)
                # move to jz instruction
                new_state = get_next_state(addr+sz)
                if new_state:
                    GRAPH[idx].append((new_state, ch))
                else:
                    print(f'no state update @ 0x{addr:x}')
                addr += 2
        addr += sz
        
    print(f'{idx = }')

open('graph.txt', 'w').write(str(GRAPH))
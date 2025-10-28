class Deobfuscator:
    def __init__(self, oep):
        self.oep = oep
        self.returns = ['ret', 'retn', 'retf']
        self.JUMP_TABLE_START = 0x140001005
        self.JUMP_TABLE_END = 0x14000482c

    def get_mnemonic(self, addr):
        return print_insn_mnem(addr)

    def get_instruction_size(self, addr):
        return DecodeInstruction(addr).size
    
    def fetch_jmp_address(self, addr):
        return get_operand_value(addr, 0)

    def check_opcode(self, addr):
        return get_bytes(addr, 1)

    def process_call(self, addr):
        # go inside callee function
        jmp_addr = self.fetch_jmp_address(addr)
        while self.JUMP_TABLE_START < jmp_addr < self.JUMP_TABLE_END:
            jmp_addr = self.fetch_jmp_address(jmp_addr)
        return jmp_addr

    def deobfuscate(self, addr):
        while True:
            mnem = self.get_mnemonic(addr)
            
            if mnem in self.returns:
                break
            
            sz = self.get_instruction_size(addr)

            # call rax
            if mnem == 'call':
                if sz == 5:
                    target = self.process_call(addr)
                    if target != addr:
                        new_rel_address = target - addr - 5
                        if new_rel_address < 0:
                            # signed
                            new_rel_address %= 2**32
                        # print(hex(addr), hex(new_rel_address), hex(target))
                        new_encoded_rel_address = struct.pack('<I', new_rel_address)
                        idaapi.patch_bytes(addr+1, new_encoded_rel_address)
            addr += sz


    def deobfuscate_init(self, method):
        if method == 1:
            for i, func in enumerate(Functions()):
                self.deobfuscate(func)
                print(f'[{i+1}] : 0x{func:x} : DONE!')
        
        elif method == 2:
            self.deobfuscate(self.oep)

        elif method == 3:
            assert SPECIFIC_FUNCTION, 'You must specify where you want to start deobfuscating from.'
            self.deobfuscate(SPECIFIC_FUNCTION)
        
        else:
            exit('[-] Not implemented yet :-(')


########################## MAIN CONFIGURATION ##########################

# Below you can choose where the deobfuscator should start working

METHODS = {
    1 : 'ALL_CALLEE_FUNCTIONS', # default
    2 : 'FROM_OEP',
    3 : 'FROM_SPECIFIC_FUNCTION'
}

SELECTED_METHOD = 3

OEP = 0x140ff6a40
SPECIFIC_FUNCTION = 0x14000C0B0

########################################################################

if __name__ == '__main__':
    deobfuscator = Deobfuscator(OEP)
    deobfuscator.deobfuscate_init(SELECTED_METHOD)
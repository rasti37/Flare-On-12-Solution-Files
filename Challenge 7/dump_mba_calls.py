for f in Functions():
    func_len = idc.get_func_attr(f, idc.FUNCATTR_END) - f
    if func_len >= 0x1eb3 or idc.get_name(f).startswith('main'):
        print(f'{f = :x}')
        addr = f
        end = idc.get_func_attr(f, idc.FUNCATTR_END)
        dmp = ''
        while addr < end:
            sz = DecodeInstruction(addr).size
            if print_insn_mnem(addr) == 'call':
                dmp += f'0x{addr:x} => {GetDisasm(addr)}\n'
            addr += sz
        if dmp != '':
            name = idc.get_name(f)
            open(f'calls/{name}.txt', 'w').write(dmp)
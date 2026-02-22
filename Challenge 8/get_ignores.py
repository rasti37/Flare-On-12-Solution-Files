end = 0x0140087ce0

ignores = []
for f in Functions():
    if f > end:
        continue
    
    ref = next(XrefsTo(f), None)
    if ref != None:
        if ref.iscode:
            continue
    
    start_ea = ida_funcs.get_func(f).start_ea
    end_ea = ida_funcs.get_func(f).end_ea
    
    if end_ea - start_ea in [4, 8]:
        ignores.append(f)

open('ignores.txt', 'w').write(str(ignores))
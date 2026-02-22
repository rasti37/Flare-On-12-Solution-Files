from SiMBA.simplify import simplify_linear_mba

expr = "((-2 * (-v41 | v41)) | ((-v41 | v41) - (-v41 & v41))) + ((-2 * (-v41 | v41)) & ((-v41 | v41) - (-v41 & v41)))"

for i in [32, 64]:
    try:
        print(i, simplify_linear_mba(expr, i, True, False))
    except:
        pass
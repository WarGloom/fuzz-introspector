import time

def test_concat():
    start = time.time()
    code = ""
    for _ in range(1000):
        code += "  /* target func */\n"
        code += "  char **new_var0 = af_get_double_char_p();\n"
        code += "  func(new_var0);\n"
        code += "\n"
    end = time.time()
    print("concat:", end - start)

def test_list():
    start = time.time()
    code_parts = []
    for _ in range(1000):
        code_parts.append("  /* target func */\n")
        code_parts.append("  char **new_var0 = af_get_double_char_p();\n")
        code_parts.append("  func(new_var0);\n")
        code_parts.append("\n")
    code = "".join(code_parts)
    end = time.time()
    print("list:", end - start)

test_concat()
test_list()

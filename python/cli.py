def print_hex_view(data):
    for i in range(0, len(data), 0x10):
        print(hex(i), ":", end=' ')
        for j in range(0, 0x10):
            if i+j < len(data):
                print(hex(data[i+j]), end=' ')
        print()

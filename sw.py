import os
import sys
from codecs import decode
from glob import glob

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: view.arg <byte sequence> <filename>")
        sys.exit()
    #file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),
    #                       sys.argv[2])
    search_pattern = decode(sys.argv[1], 'hex')
    num_chars = len(search_pattern)

    for file_path in glob(sys.argv[2]):
        with open(file_path, 'rb') as f:
            data = f.read(num_chars)

        if data.startswith(search_pattern):
            print('match: {0}'.format(file_path))
        else:
            pass
            #print('no match')

import os
import sys
from pprint import pprint
from resources.terrain import TerrainFile
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: t.py <filename>")
        print(sys.argv)
        sys.exit()
    file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             sys.argv[1])
    with open(file_path, 'rb') as f:
        t = TerrainFile(f.read())
        pprint(t.boundary)
        print(len(t.positions))
        pprint(t.positions)
    #print_hex_view(t.extracted)

from pathlib import Path, PureWindowsPath

from cmp import CmpFile
from piv import PivFile
from font import FontFile
from t import TFile
from settings import MOONSTONE_DIR


def load_file(file_type, filename):
    file_path = Path(MOONSTONE_DIR) / PureWindowsPath(filename)
    with open(file_path, 'rb') as f:
        data = f.read()
    return file_type(data)


backgrounds = {
    'ch': load_file(PivFile, 'DISKB\CH.PIV'),
    'wab1': load_file(PivFile, 'DISKB\WAB1.CMP'),
}

scenery_files = {
    'fo1': load_file(CmpFile, 'DISKB\FO1.CMP'),
    'fo2': load_file(CmpFile, 'DISKB\FO2.CMP'),
    'sw1': load_file(CmpFile, 'DISKB\SW1.CMP'),
    'wa1': load_file(CmpFile, 'DISKB\WA1.CMP'),
}

fonts = {
    'bold': load_file(FontFile, 'DISKA\BOLD.F'),
    'small': load_file(FontFile, 'DISKB\SMALL.FON'),
}

objects = {
    'kn1': load_file(FontFile, 'DISKB\KN1.OB'),
    'kn4': load_file(FontFile, 'DISKB\KN4.OB'),
}

terrain = {
    'wa1': load_file(TFile, 'DISKB\WA1.T'),
}

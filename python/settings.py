from pathlib import Path
from configparser import ConfigParser


config = ConfigParser()
config.read(['settings.ini'])
config['moonstone']['home_dir'] = config['moonstone'].get('home_dir', str(Path.home()))

SCALE_FACTOR = config.getint('moonstone', 'scale_factor')
FRAME_LIMIT = config.getint('moonstone', 'frame_limit')
MOONSTONE_DIR = config['moonstone']['moonstone_dir']
DEBUG = config.getboolean('moonstone', 'debug')

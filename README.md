# OpenMoonstone
An open source reimplementation of the Amiga/DOS game [Moonstone](https://en.wikipedia.org/wiki/Moonstone:_A_Hard_Days_Knight)
## Windows
Download the latest release from https://github.com/joetsoi/OpenMoonstone/releases
You'll need to edit the settings.ini file with the location of the original moonstone DOS version
after that run moonstone.exe
### Controls
* Player one: arrow keys and space
* Player two: WASD and F
## Configuration
You need a DOS copy of the original moonstone. Extract it to your home dir
either `~/games/moonstone` for linux or `C:\Users\username\games\moonstone`

### settings.ini
Change `MOONSTONE_DIR` in `settings.ini` to match that same directory. You can
use `%(home_dir)s` to mean `~/` or `Users/<your user>`

##### Scale factor
This is set to 3 as default, change to increase or decrease the size or the
window

## Running
```
python view.py
````
### Progress videos
https://www.youtube.com/watch?v=41iNdWDJwUY&list=PLub5fMuLNSIoc0oVM2NJSzmA4HHv1k_Ue

# OpenMoonstone
An open source reimplementation of the Amiga/DOS game [Moonstone](https://en.wikipedia.org/wiki/Moonstone:_A_Hard_Days_Knight)
## Source Install
## Configuration
You need a DOS copy of the original moonstone. Extract it to your home dir
either `~/games/moonstone` for linux or `C:\Users\username\games\moonstone`

Change `MOONSTONE_DIR` in `settings.ini` to match that same directory. You can
use `%(home_dir)s` to mean `~/` or `Users/<your user>`

##### Scale factor
This is set to 3 as default, change to increase or decrease the size or the
window

## Running
```
python view.py
````
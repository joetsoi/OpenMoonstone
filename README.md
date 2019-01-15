# OpenMoonstone
An open source reimplementation of the Amiga/DOS game [Moonstone](https://en.wikipedia.org/wiki/Moonstone:_A_Hard_Days_Knight)

## Running
### Windows
Download the latest windows build from https://github.com/joetsoi/OpenMoonstone/releases
You need a DOS copy of the original moonstone. This should be extracted, renamed to 
`moonstone` and placed underthe `resources` directory. Then you can run `openmoonstone.exe`

### Other platforms
OpenMoonstone should build and run on all platforms supported by both Rust and SDL2.

https://forge.rust-lang.org/platform-support.html

Currently only Ubuntu and Windows have been tested.

### Controls
* Player one: arrow keys and space
* Player two: WASD and Left Ctrl
* Player three: IJKL and G
* Player four: Numpad 8456 and Numpad enter

### Configuration
#### Fullscreen
You run in full screen mode by changing `fullscreen_type` from `"Off"` to `"Desktop"`

##  Developement
Requires [rust nightly](https://www.rust-lang.org/tools/install)
```
cd rust
cargo run
```
### Progress videos
https://www.youtube.com/watch?v=41iNdWDJwUY&list=PLub5fMuLNSIoc0oVM2NJSzmA4HHv1k_Ue

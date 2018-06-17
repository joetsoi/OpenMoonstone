extern crate openmoonstone;

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    let filename = &args[1];

    match openmoonstone::piv::PivImage::from_file(filename) {
        Ok(piv) => {
            //println!("{:?}", piv);
            println!("done");
        }
        Err(e) => {
            println!("Application error: {}", e);
            process::exit(1);
        }
    };
}

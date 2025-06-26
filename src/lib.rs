#![allow(dead_code)] 
mod proto;
mod func;
#[macro_use]
extern crate litcrypt;
 
use_litcrypt!();

pub extern "system" fn main() {
    proto::Pick();
}

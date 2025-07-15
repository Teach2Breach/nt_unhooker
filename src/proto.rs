use crate::func;

use_litcrypt!();

pub fn pick() {
    //clean all hooks
    if func::check_and_unhook() {
        println!("{}", lc!("Successfully unhooked all hooks"));
    } else {
        println!("{}", lc!("Failed to unhook all hooks"));
    }
}
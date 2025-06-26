use crate::func;

use_litcrypt!();

#[no_mangle]
pub extern "system" fn Pick() {

    //clean all hooks
    if func::check_and_unhook() {
        println!("{}", lc!("Successfully unhooked all hooks"));
    } else {
        println!("{}", lc!("Failed to unhook all hooks"));
    }

}
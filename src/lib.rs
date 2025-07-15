#![allow(dead_code)] 
mod proto;
mod func;
#[macro_use]
extern crate litcrypt;
 
use_litcrypt!();

// Re-export the main functions from func module
pub use func::{
    check_and_unhook,
    get_ntdll_symbol_info,
    get_clean_ntdll,
    unhook_iat,
    unhook_ntdll,
    check_hooks,
    check_iat_hooks,
    get_clean_function_address,
    PeInfo,
};

// Keep the original entry point for backward compatibility
#[no_mangle]
pub extern "system" fn Pick() {
    proto::pick();
}

// Optional: Provide a more ergonomic API
pub struct NtUnhooker;

impl NtUnhooker {
    /// Check and unhook NTDLL functions in the current process
    pub fn unhook() -> bool {
        check_and_unhook()
    }
    
    /// Unhook NTDLL without checking (assumes you have clean_dll and ntdll handle)
    pub fn unhook_direct(clean_dll: &[u8], ntdll: *mut std::ffi::c_void) -> bool {
        unsafe { 
            use winapi::ctypes::c_void;
            unhook_ntdll(clean_dll, ntdll as *mut c_void) 
        }
    }
    
    /// Get NTDLL symbol information
    pub fn get_symbol_info() -> Option<PeInfo> {
        get_ntdll_symbol_info()
    }
    
    /// Download a clean version of NTDLL
    pub fn download_clean_ntdll() -> Option<Vec<u8>> {
        get_clean_ntdll()
    }
}

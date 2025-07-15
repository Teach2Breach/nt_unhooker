use nt_unhooker::{NtUnhooker, check_and_unhook, get_ntdll_symbol_info, PeInfo};

fn main() {
    println!("NT Unhooker Library Example");
    println!("==========================");
    
    // Method 1: Using the ergonomic API
    println!("\n1. Using NtUnhooker struct:");
    match NtUnhooker::get_symbol_info() {
        Some(info) => {
            println!("   NTDLL Symbol Info:");
            println!("   - Timestamp: {:#x}", info.timestamp);
            println!("   - Size: {:#x}", info.size);
            println!("   - PDB: {}", info.pdb_name);
            println!("   - GUID: {}", info.guid);
        }
        None => println!("   Failed to get symbol info"),
    }
    
    // Method 2: Using direct function calls
    println!("\n2. Using direct function calls:");
    if let Some(clean_ntdll) = nt_unhooker::get_clean_ntdll() {
        println!("   Successfully downloaded clean NTDLL: {} bytes", clean_ntdll.len());
    } else {
        println!("   Failed to download clean NTDLL");
    }
    
    // Method 3: Perform full unhooking
    println!("\n3. Performing unhooking:");
    if check_and_unhook() {
        println!("   ✓ Unhooking completed successfully");
    } else {
        println!("   ✗ Unhooking failed");
    }
    
    // Method 4: Using the struct method
    println!("\n4. Using struct method:");
    if NtUnhooker::unhook() {
        println!("   ✓ Unhooking completed successfully");
    } else {
        println!("   ✗ Unhooking failed");
    }
} 
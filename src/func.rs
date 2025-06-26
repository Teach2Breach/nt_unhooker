#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::mem;
use ntapi::ntldr::LdrGetDllHandle;
use reqwest;
use winapi::um::memoryapi::WriteProcessMemory;
use std::ffi::CString;
use winapi::shared::ntdef::{PVOID, NTSTATUS, UNICODE_STRING, HANDLE};

use winapi::um::winnt::{
    IMAGE_DEBUG_DIRECTORY,
    IMAGE_DEBUG_TYPE_CODEVIEW,
    IMAGE_DIRECTORY_ENTRY_DEBUG,
    IMAGE_DOS_HEADER,
    IMAGE_NT_HEADERS,
    IMAGE_SECTION_HEADER,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_EXPORT,
};

#[derive(Debug)]
pub struct PeInfo {
    pub timestamp: u32,
    pub size: u32,
    pub pdb_name: String,
    pub guid: String,
    pub age: u32,
}

#[repr(C)]
struct RSDS_DEBUG_FORMAT {
    Rsds: u32,
    Guid: GUID,
    Age: u32,
    PdbFileName: [u8; 260],  // Adjust size as needed
}

#[repr(C)]
struct GUID {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [u8; 8],
}

#[repr(C)]
struct IMAGE_IMPORT_DESCRIPTOR {
    OriginalFirstThunk: u32,
    TimeDateStamp: u32,
    ForwarderChain: u32,
    Name: u32,
    FirstThunk: u32,
}

#[repr(C)]
struct IMAGE_THUNK_DATA {
    u1: IMAGE_THUNK_DATA_U1,
}

#[repr(C)]
union IMAGE_THUNK_DATA_U1 {
    ForwarderString: u64,
    Function: u64,
    Ordinal: u64,
    AddressOfData: u64,
}

#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
}

#[allow(non_snake_case)]
type LdrGetProcedureAddress = unsafe extern "system" fn(
    ModuleHandle: PVOID,
    FunctionName: *const UNICODE_STRING,
    Ordinal: u32,
    FunctionAddress: *mut PVOID,
) -> NTSTATUS;

// Function types from NTDLL
type LdrGetDllHandle_t = unsafe extern "system" fn(
    PathToFile: PVOID,
    PathToFileDos: PVOID,
    ModuleFileName: *const UNICODE_STRING,
    ModuleHandle: *mut PVOID,
) -> NTSTATUS;

type NtWriteVirtualMemory_t = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    Buffer: PVOID,
    NumberOfBytesToWrite: usize,
    NumberOfBytesWritten: *mut usize,
) -> NTSTATUS;

type NtProtectVirtualMemory_t = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    RegionSize: *mut usize,
    NewProtect: u32,
    OldProtect: *mut u32,
) -> NTSTATUS;

type WriteProcessMemory_t = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    Buffer: PVOID,
    Size: usize,
    NumberOfBytesWritten: *mut usize,
) -> i32;

const NT_CURRENT_PROCESS: HANDLE = -1isize as HANDLE;

fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn get_ntdll_symbol_info() -> Option<PeInfo> {
    unsafe {
        let dll_name = wide_string(&lc!("ntdll.dll"));
        let name_len = (dll_name.len() - 1) * 2;  // exclude null terminator, but multiply by 2 for wide chars
        let mut unicode_name = UNICODE_STRING {
            Length: name_len as u16,
            MaximumLength: (dll_name.len() * 2) as u16,  // include space for null terminator
            Buffer: dll_name.as_ptr() as *mut _,
        };

        println!("String length: {}, Maximum length: {}", name_len, dll_name.len() * 2);
        println!("Buffer contents: {:?}", dll_name);

        let mut ntdll: PVOID = std::ptr::null_mut();
        let status = LdrGetDllHandle(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut unicode_name,
            &mut ntdll
        );
        
        if status != 0 {
            println!("LdrGetDllHandle failed with status: {:#x}", status);
            return None;
        }

        if ntdll.is_null() {
            println!("LdrGetDllHandle returned null handle");
            return None;
        }
        
        let dos_header = ntdll as *const IMAGE_DOS_HEADER;
        let nt_headers = (ntdll as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        
        // Get timestamp and size from PE header
        let timestamp = (*nt_headers).FileHeader.TimeDateStamp;
        let size = (*nt_headers).OptionalHeader.SizeOfImage;

        // Find debug directory
        let debug_dir = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG as usize];
        let debug_rva = debug_dir.VirtualAddress;
        
        if debug_rva != 0 {
            let debug_entry = (ntdll as usize + debug_rva as usize) as *const IMAGE_DEBUG_DIRECTORY;
            if (*debug_entry).Type == IMAGE_DEBUG_TYPE_CODEVIEW {
                let pdb_info = (ntdll as usize + (*debug_entry).AddressOfRawData as usize) as *const RSDS_DEBUG_FORMAT;
                
                // Extract PDB GUID
                let guid = format!("{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                    (*pdb_info).Guid.Data1,
                    (*pdb_info).Guid.Data2,
                    (*pdb_info).Guid.Data3,
                    (*pdb_info).Guid.Data4[0],
                    (*pdb_info).Guid.Data4[1],
                    (*pdb_info).Guid.Data4[2],
                    (*pdb_info).Guid.Data4[3],
                    (*pdb_info).Guid.Data4[4],
                    (*pdb_info).Guid.Data4[5],
                    (*pdb_info).Guid.Data4[6],
                    (*pdb_info).Guid.Data4[7]
                );

                let pdb_name = std::ffi::CStr::from_ptr((*pdb_info).PdbFileName.as_ptr() as *const i8)
                    .to_string_lossy()
                    .into_owned();

                return Some(PeInfo {
                    timestamp,
                    size,
                    pdb_name,
                    guid,
                    age: (*pdb_info).Age,
                });
            }
        }
        None
    }
}

pub fn get_clean_ntdll() -> Option<Vec<u8>> {
    let pe_info = get_ntdll_symbol_info()?;
    
    // Build symbol path for DLL download
    // Format: https://msdl.microsoft.com/download/symbols/ntdll.dll/HASH/ntdll.dll
    let symbol_path = format!(
        "https://msdl.microsoft.com/download/symbols/ntdll.dll/{:X}{:X}/ntdll.dll", 
        pe_info.timestamp,
        pe_info.size
    );

    println!("{}: {}", lc!("Attempting download from"), symbol_path);

    // Create blocking HTTP client with longer timeout
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .ok()?;

    // Try download with retry logic
    let mut retries = 3;
    let mut response = None;
    
    while retries > 0 {
        match client.get(&symbol_path).send() {
            Ok(resp) => {
                if resp.status().is_success() {
                    response = Some(resp);
                    break;
                }
                println!("{}: {} (attempts remaining: {})", 
                    lc!("Download failed with status"),
                    resp.status(),
                    retries - 1
                );
            }
            Err(e) => {
                println!("{}: {} (attempts remaining: {})",
                    lc!("Download error"),
                    e,
                    retries - 1
                );
            }
        }
        retries -= 1;
        if retries > 0 {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    let response = response?;

    // Get the bytes
    let clean_dll = match response.bytes() {
        Ok(bytes) => bytes.to_vec(),
        Err(e) => {
            println!("{}: {}", lc!("Failed to read response bytes"), e);
            return None;
        }
    };

    // Verify the downloaded DLL
    unsafe {
        // Check if it's a valid PE file
        if clean_dll.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
            println!("{}", lc!("Downloaded file too small"));
            return None;
        }

        let dos_header = clean_dll.as_ptr() as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D { // "MZ" signature
            println!("{}", lc!("Invalid DOS header signature"));
            return None;
        }

        // Verify PE header
        let nt_headers = (clean_dll.as_ptr() as usize + (*dos_header).e_lfanew as usize) 
            as *const IMAGE_NT_HEADERS;
        if (*nt_headers).Signature != 0x4550 { // "PE" signature
            println!("{}", lc!("Invalid PE signature"));
            return None;
        }

        // Verify timestamp matches
        if (*nt_headers).FileHeader.TimeDateStamp != pe_info.timestamp {
            println!("{}", lc!("Timestamp mismatch in downloaded file"));
            return None;
        }
    }

    println!("{}: {} bytes", lc!("Successfully downloaded clean NTDLL"), clean_dll.len());
    Some(clean_dll)
}

//take ntdll base address as a parameter
fn check_hooks(clean_dll: &[u8], ntdll: PVOID) {
    unsafe {
        // First get clean LdrGetProcedureAddress
        let ldr_getproc = match get_clean_function_address(clean_dll, "LdrGetProcedureAddress")
            .map(|addr| ntdll as usize + (addr - clean_dll.as_ptr() as usize))
            .map(|addr| std::mem::transmute::<usize, LdrGetProcedureAddress>(addr)) {
                Some(func) => func,
                None => return,
        };
        
        let functions = [
            "NtCreateFile",
            "NtOpenProcess",
            "NtOpenThread",
            "NtCreateThreadEx",
            "NtMapViewOfSection",
            "NtProtectVirtualMemory",
            "NtWriteVirtualMemory",
            "NtAllocateVirtualMemory",
        ];

        for func_name in &functions {
            let name = CString::new(*func_name).unwrap();
            let mut unicode_name = UNICODE_STRING {
                Length: name.as_bytes_with_nul().len() as u16,
                MaximumLength: name.as_bytes_with_nul().len() as u16,
                Buffer: name.as_ptr() as *mut _,
            };
            
            let mut func_addr: PVOID = std::ptr::null_mut();
            if ldr_getproc(
                ntdll,
                &unicode_name,
                0,
                &mut func_addr
            ) == 0 {
                let bytes = std::slice::from_raw_parts(func_addr as *const u8, 16);
                print!("{}: ", func_name);
                for byte in bytes {
                    print!("{:02X} ", byte);
                }
                
                let is_hooked = if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 {
                    match bytes[3] {
                        0xE9 => true,  // JMP instruction
                        0xB8 => false, // Normal syscall
                        _ => true      // Unknown pattern
                    }
                } else {
                    true  // Unexpected start sequence
                };

                if is_hooked {
                    println!(" [HOOKED]");
                } else {
                    println!(" [CLEAN]");
                }
            }
        }
    }
}

pub fn check_and_unhook() -> bool {
    // Download clean NTDLL once
    let clean_dll = match get_clean_ntdll() {
        Some(dll) => dll,
        None => {
            println!("{}", lc!("Failed to download clean NTDLL"));
            return false;
        }
    };

    println!("Starting unhooking process...");

    let dll_name = wide_string(&lc!("ntdll.dll"));
    let mut unicode_name = UNICODE_STRING {
        Length: ((dll_name.len() - 1) * 2) as u16,
        MaximumLength: (dll_name.len() * 2) as u16,
        Buffer: dll_name.as_ptr() as *mut _,
    };

    let mut ntdll: PVOID = std::ptr::null_mut();
    println!("Getting NTDLL handle...");

    if unsafe { LdrGetDllHandle(
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut unicode_name,
        &mut ntdll
    ) } != 0 {
        println!("Failed to get NTDLL handle");
        return false;
    }

    println!("NTDLL handle obtained: {:p}", ntdll);

    println!("\nChecking current hook status:");
    println!("\n[Inline Hooks]");
    check_hooks(&clean_dll, ntdll);
    println!("\n[IAT Hooks]");
    check_iat_hooks(&clean_dll, ntdll);

    // Perform unhooking operations
    println!("\nUnhooking operations:");
    
    println!("Starting inline hook removal...");
    let inline_result = unhook_ntdll(&clean_dll, ntdll);
    if !inline_result {
        println!("{}", lc!("Failed to unhook inline hooks"));
        return false;
    }
    println!("✓ Inline hooks removed");

    println!("Starting IAT hook removal...");
    let iat_result = unhook_iat(&clean_dll, ntdll);
    if !iat_result {
        println!("{}", lc!("Failed to unhook IAT"));
        return false;
    }
    println!("✓ IAT hooks removed");

    // Final verification
    println!("\nVerifying final state:");
    println!("\n[Inline Hooks]");
    check_hooks(&clean_dll, ntdll);
    println!("\n[IAT Hooks]");
    check_iat_hooks(&clean_dll, ntdll);

    println!("\n{}", lc!("Successfully completed all unhooking operations"));
    true
}

fn unhook_ntdll(clean_dll: &[u8], ntdll: PVOID) -> bool {
    unsafe {
        println!("Processing sections...");
        let dos_header = ntdll as *const IMAGE_DOS_HEADER;
        let nt_headers = (ntdll as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        let sections = (nt_headers as usize + mem::size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;

        for i in 0..(*nt_headers).FileHeader.NumberOfSections {
            let section = &*sections.add(i as usize);
            let section_name = std::str::from_utf8_unchecked(&section.Name);
            println!("Processing section: {}", section_name);
            
            if !section_name.starts_with(".text") {
                continue;
            }

            println!("Found .text section at RVA: {:#x}, Raw offset: {:#x}, Size: {:#x}", 
                section.VirtualAddress, 
                section.PointerToRawData,
                section.SizeOfRawData);

            let base_addr = (ntdll as usize + section.VirtualAddress as usize) as *mut _;
            let clean_data = clean_dll.as_ptr().add(section.PointerToRawData as usize);
            let mut bytes_written = 0;

            println!("Writing clean section at {:p} with size {:#x}", base_addr, section.SizeOfRawData);
            
            let result = WriteProcessMemory(
                NT_CURRENT_PROCESS,
                base_addr,
                clean_data as *const _ as PVOID,
                section.SizeOfRawData as usize,
                &mut bytes_written
            );

            if result == 0 {
                println!("WriteProcessMemory failed");
                return false;
            }

            println!("Successfully wrote {} bytes", bytes_written);
            return true;
        }
        false
    }
}

fn get_clean_function_address(clean_dll: &[u8], function_name: &str) -> Option<usize> {
    unsafe {
        let dos_header = clean_dll.as_ptr() as *const IMAGE_DOS_HEADER;
        let nt_headers = (clean_dll.as_ptr() as usize + (*dos_header).e_lfanew as usize) 
            as *const IMAGE_NT_HEADERS;
        
        let export_dir = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        let export_directory = (clean_dll.as_ptr() as usize + export_dir.VirtualAddress as usize) 
            as *const IMAGE_EXPORT_DIRECTORY;
        
        let names = std::slice::from_raw_parts(
            (clean_dll.as_ptr() as usize + (*export_directory).AddressOfNames as usize) as *const u32,
            (*export_directory).NumberOfNames as usize
        );
        
        let ordinals = std::slice::from_raw_parts(
            (clean_dll.as_ptr() as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
            (*export_directory).NumberOfNames as usize
        );
        
        let functions = std::slice::from_raw_parts(
            (clean_dll.as_ptr() as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
            (*export_directory).NumberOfFunctions as usize
        );

        // Find the function by name
        for i in 0..(*export_directory).NumberOfNames as usize {
            let name_rva = names[i];
            let name_ptr = (clean_dll.as_ptr() as usize + name_rva as usize) as *const i8;
            let name = std::ffi::CStr::from_ptr(name_ptr).to_str().ok()?;
            
            if name == function_name {
                let ordinal = ordinals[i] as usize;
                let function_rva = functions[ordinal];
                return Some(clean_dll.as_ptr() as usize + function_rva as usize);
            }
        }
        None
    }
}

pub fn unhook_iat(clean_dll: &[u8], ntdll: PVOID) -> bool {
    unsafe {
        extern "C" {
            static __ImageBase: u8;
        }
        let current_module = &__ImageBase as *const u8 as PVOID;

        let dos_header = current_module as *const IMAGE_DOS_HEADER;
        let nt_headers = (current_module as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        let import_dir = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
        let mut import_desc = (current_module as usize + import_dir.VirtualAddress as usize) 
            as *const IMAGE_IMPORT_DESCRIPTOR;

        let skip_functions = [
            "LdrGetDllHandle",
            "WriteProcessMemory",
        ];

        let mut hooks_removed = 0;
        while (*import_desc).Name != 0 {
            let dll_name = std::ffi::CStr::from_ptr((current_module as usize + (*import_desc).Name as usize) 
                as *const i8).to_string_lossy();

            if dll_name.eq_ignore_ascii_case("ntdll.dll") {
                let mut thunk = (current_module as usize + (*import_desc).FirstThunk as usize) 
                    as *mut IMAGE_THUNK_DATA;
                let mut orig_thunk = (current_module as usize + (*import_desc).OriginalFirstThunk as usize) 
                    as *const IMAGE_THUNK_DATA;

                while (*thunk).u1.Function != 0 {
                    let func_name = (current_module as usize + (*orig_thunk).u1.AddressOfData as usize + 2) 
                        as *const i8;
                    if let Ok(func_name_str) = std::ffi::CStr::from_ptr(func_name).to_str() {
                        if !skip_functions.contains(&func_name_str) {  // Skip our critical functions
                            if let Some(clean_addr) = get_clean_function_address(clean_dll, func_name_str) {
                                let clean_rva = clean_addr - clean_dll.as_ptr() as usize;
                                let new_addr = ntdll as usize + clean_rva;
                                
                                if (*thunk).u1.Function as usize != new_addr {
                                    let mut bytes_written = 0;
                                    let result = WriteProcessMemory(
                                        NT_CURRENT_PROCESS,
                                        &mut (*thunk).u1 as *mut _ as *mut _,
                                        &new_addr as *const _ as *const _,
                                        std::mem::size_of::<usize>(),
                                        &mut bytes_written
                                    );

                                    if result == 0 {
                                        println!("Failed to patch IAT entry for {}", func_name_str);
                                        return false;
                                    }
                                    hooks_removed += 1;
                                }
                            }
                        }
                    }
                    thunk = thunk.add(1);
                    orig_thunk = orig_thunk.add(1);
                }
                break;
            }
            import_desc = import_desc.add(1);
        }
        
        if hooks_removed > 0 {
            println!("Removed {} IAT hooks", hooks_removed);
        }
        true
    }
}

fn check_iat_hooks(clean_dll: &[u8], ntdll: PVOID) {
    unsafe {
        extern "C" {
            static __ImageBase: u8;
        }
        let current_module = &__ImageBase as *const u8 as PVOID;

        let dos_header = current_module as *const IMAGE_DOS_HEADER;
        let nt_headers = (current_module as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        let import_dir = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
        let mut import_desc = (current_module as usize + import_dir.VirtualAddress as usize) 
            as *const IMAGE_IMPORT_DESCRIPTOR;

        let functions = [
            "NtCreateFile",
            "NtOpenProcess",
            "NtOpenThread",
            "NtCreateThreadEx",
            "NtMapViewOfSection",
            "NtProtectVirtualMemory",
            "NtWriteVirtualMemory",
            "NtAllocateVirtualMemory",
        ];

        while (*import_desc).Name != 0 {
            let dll_name = std::ffi::CStr::from_ptr((current_module as usize + (*import_desc).Name as usize) 
                as *const i8).to_string_lossy();

            if dll_name.eq_ignore_ascii_case("ntdll.dll") {
                let mut thunk = (current_module as usize + (*import_desc).FirstThunk as usize) 
                    as *mut IMAGE_THUNK_DATA;
                let mut orig_thunk = (current_module as usize + (*import_desc).OriginalFirstThunk as usize) 
                    as *const IMAGE_THUNK_DATA;

                // Create a mutable copy of functions to track which ones we've found
                let mut functions_to_check = functions.to_vec();

                while (*thunk).u1.Function != 0 {
                    let func_name = (current_module as usize + (*orig_thunk).u1.AddressOfData as usize + 2) 
                        as *const i8;
                    if let Ok(func_name_str) = std::ffi::CStr::from_ptr(func_name).to_str() {
                        if let Some(pos) = functions_to_check.iter().position(|&f| f == func_name_str) {
                            functions_to_check.remove(pos);  // Remove from list once found
                            let current_addr = (*thunk).u1.Function as usize;
                            
                            // Get first 16 bytes of the function
                            let bytes = std::slice::from_raw_parts(current_addr as *const u8, 16);
                            print!("{}: ", func_name_str);
                            for byte in bytes {
                                print!("{:02X} ", byte);
                            }
                            
                            if let Some(expected_addr) = get_clean_function_address(clean_dll, func_name_str) {
                                let expected_rva = expected_addr - clean_dll.as_ptr() as usize;
                                let current_rva = current_addr - ntdll as usize;
                                
                                if current_rva != expected_rva {
                                    println!(" [HOOKED]");
                                } else {
                                    println!(" [CLEAN]");
                                }
                            } else {
                                println!(" [ERROR: Not found in clean DLL]");
                            }
                        }
                    }
                    thunk = thunk.add(1);
                    orig_thunk = orig_thunk.add(1);
                }

                // Print any functions we didn't find in the IAT
                for missing_func in functions_to_check {
                    println!("{}: Not found in IAT", missing_func);
                }
                break;
            }
            import_desc = import_desc.add(1);
        }
    }
}
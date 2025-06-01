/*
    What is this exactly?
    ------------------------
    This is a memory reading / writing, pattern scanning,
    and thread debugging utility meant for a general purpose use.

    Why did I develop this?
    -----------------------
    Due to the lack of memory utilities that just ease your job and
    don't make you use them like a baby with toys. And also I like
    debugging processes to see what they are doing exactly.

    Where can I find the source?
    ---------------------------
    https://github.com/penguin-cmyk/memory_utils

 */

/*
    TODO: VTable hooking,
          IAT (Import Address Table)  hooking,
          EAT (Export Address Table) hooking,
          remove module entries from the VAD (Virtual Address Descriptor),
          unlinking PEB (Process Environment Block),
          DLL Handling
 */

// Imports
use winapi::{
    um::{
        handleapi::{ CloseHandle, INVALID_HANDLE_VALUE },

        memoryapi::{
            WriteProcessMemory,
            ReadProcessMemory,
            VirtualQueryEx,
            VirtualProtectEx,
            VirtualAllocEx,
            VirtualFreeEx
        },

        processthreadsapi::{
            OpenProcess,
            OpenThread,
            SuspendThread,
            ResumeThread,
            GetThreadContext,
            TerminateProcess
        },

        tlhelp32::{
            CreateToolhelp32Snapshot,
            Thread32First,
            TH32CS_SNAPPROCESS,
            THREADENTRY32,
            Thread32Next,
            Process32First,
            Process32Next,
            PROCESSENTRY32,
            TH32CS_SNAPTHREAD,
            MODULEENTRY32,
            TH32CS_SNAPMODULE,
            TH32CS_SNAPMODULE32,
            Module32First,
            Module32Next
        },

        winnt::*,
    },

    shared::{
        minwindef::{LPVOID, DWORD, LPCVOID} ,
    },
};

use std::{
    io::{ Error, ErrorKind },
    mem::{ zeroed, size_of },
    ffi::CStr,
    ptr,
    str,
    fs,
    slice,
    u32
};

// Enum and Structs
pub struct Process {
    pub pid: u32,
    pub handle: HANDLE,
}

unsafe impl Send for Process {}
unsafe impl Sync for Process {}


/// Contains:
/// * `name`: String
/// * `base_address`:  LPVOID,
/// * `entry`:  MODULEENTRY32
pub struct ModuleInfo {
    pub name: String,
    pub base_address: LPVOID,
    pub entry: MODULEENTRY32
}
#[derive(Debug)]
/// Contains:
/// * `stack_ptr`:  LPCVOID
/// * `buffer`: Vector of u8,
/// * `base_address`: LPVOID,
/// * `stack_size`: usize
pub struct Stack {
    pub stack_ptr: LPCVOID,
    pub buffer: Vec<u8>,
    pub base_address: LPVOID,
    pub stack_size: usize,
}
#[derive(Debug)]
/// Contains:
/// * `name`: String
/// * `virtual_address`: LPVOID
/// * `virtual_size`: usize
/// * `dumped_path`: String
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: usize,
    pub virtual_address: LPVOID,
    pub dumped_path: String
}

/// Contains:
/// * `export_info`: IMAGE_EXPORT_DIRECTORY
/// * `export_directory_address`: LPVOID
pub struct ExportInfo {
    pub export_info: IMAGE_EXPORT_DIRECTORY,
    pub export_directory_address: LPVOID,
}

pub struct Instruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
}


/// Contains:
/// * `sections`: Vector of [`SectionInfo`]
/// * `export`: Option of [`ExportInfo`]
pub struct PeInfo {
    pub sections: Vec<SectionInfo>,
    pub exports: Option<ExportInfo>,
}

#[derive(Debug)]
pub enum ProtectOptions {
    NoAccess,
    ReadOnly,
    ReadWrite,
    WriteCopy,
    Execute,
    ExecuteRead,
    ExecuteReadWrite,
    ExecuteWriteCopy,
    Guard,
    NoCache,
    WriteCombine,
}

impl From<ProtectOptions> for u32 {
    fn from(opt: ProtectOptions) -> Self {
        match opt {
            ProtectOptions::NoAccess => PAGE_NOACCESS,
            ProtectOptions::ReadOnly => PAGE_READONLY,
            ProtectOptions::ReadWrite => PAGE_READWRITE,
            ProtectOptions::WriteCopy => PAGE_WRITECOPY,
            ProtectOptions::Execute => PAGE_EXECUTE,
            ProtectOptions::ExecuteRead => PAGE_EXECUTE_READ,
            ProtectOptions::ExecuteReadWrite => PAGE_EXECUTE_READWRITE,
            ProtectOptions::ExecuteWriteCopy => PAGE_EXECUTE_WRITECOPY,
            ProtectOptions::Guard => PAGE_GUARD,
            ProtectOptions::NoCache => PAGE_NOCACHE,
            ProtectOptions::WriteCombine => PAGE_WRITECOMBINE,
        }
    }
}

impl From<u32> for ProtectOptions {
    fn from(opt: u32) -> Self {
        match opt {
            PAGE_NOACCESS => ProtectOptions::NoAccess,
            PAGE_READONLY => ProtectOptions::ReadOnly,
            PAGE_READWRITE => ProtectOptions::ReadWrite,
            PAGE_WRITECOPY => ProtectOptions::WriteCopy,
            PAGE_EXECUTE => ProtectOptions::Execute,
            PAGE_EXECUTE_READ => ProtectOptions::ExecuteRead,
            PAGE_EXECUTE_READWRITE => ProtectOptions::ExecuteReadWrite,
            PAGE_EXECUTE_WRITECOPY => ProtectOptions::ExecuteWriteCopy,
            PAGE_GUARD => ProtectOptions::Guard,
            PAGE_NOCACHE => ProtectOptions::NoCache,
            PAGE_WRITECOMBINE => ProtectOptions::WriteCombine,
            _ => ProtectOptions::NoAccess, // shouldn't happen since we covered all protection from above, but just in case
        }
    }
}

// Entry to the main functionality
impl Process {

    /// "Clones" the process / makes a new Process struct that inherits the previous handle and pid
    pub fn clone(&self) -> Process {
        Process {
            pid: self.pid,
            handle: self.handle,
        }
    }

    /// Creates a new Process handler with the given in Process ID.
    ///
    /// Aswell it will automatically inherit the "handle" with these permissions:
    /// - `PROCESS_VM_READ`
    /// - `PROCESS_QUERY_INFORMATION`
    /// - `PROCESS_VM_WRITE`
    ///-  `PROCESS_VM_OPERATION`
    pub fn new(pid: u32) -> Self {
        let handle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, pid) };
        Self {
            pid,
            handle
        }
    }

    /// Writes a byte slice (`&[u8]`) into another process's memory at the specified address.
    ///
    /// This function provides a safe abstraction over the Windows API `WriteProcessMemory`,
    /// allowing arbitrary bytes to be written to a foreign process's address space. It is
    /// primarily intended for use in external memory manipulation, such as modding or debugging.
    ///
    /// # Parameters
    ///
    /// - `address`: The target address in the remote process's memory where the data should be written.
    /// - `bytes`: A reference to a byte slice containing the data to write.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the entire byte slice was successfully written to the target memory.
    /// Returns `Err(std::io::Error)` if the memory operation fails.
    ///
    /// # Errors
    ///
    /// This function returns an error if:
    /// - The address is invalid or inaccessible in the target process.
    /// - The process handle is invalid or lacks sufficient access rights.
    /// - Only a partial write occurs (i.e., fewer bytes are written than expected).
    ///
    /// # Safety
    ///
    /// This function performs raw memory writes into another process's address space,
    /// which is inherently unsafe. It assumes:
    /// - The address is valid and writable in the target process.
    /// - The caller has properly obtained and validated the process handle with
    ///   `PROCESS_VM_WRITE | PROCESS_VM_OPERATION` rights.
    ///
    /// Improper use may corrupt memory or cause the target process to crash.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let roblox = Process::new(1234);
    /// let address = 0x00FF_1234_5678;
    /// let data = b"hello";
    /// roblox.write_bytes(address, data).expect("Failed to write memory");
    /// ```
    pub fn write_bytes(&self, address: usize, bytes: &[u8]) -> Result<(), Error> {
        unsafe {
            let mut bytes_written = 0;
            let success = WriteProcessMemory(
                self.handle,
                address as LPVOID,
                bytes.as_ptr() as LPCVOID,
                bytes.len(),
                &mut bytes_written
            );

            if success == 0 || bytes_written != bytes.len() {
                return Err(Error::last_os_error());
            }

            Ok(())
        }
    }

    /// This sanitizes the inputted bytes and removes non-printable character and null terminators
    pub fn sanitize_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        bytes
            .iter()
            .cloned()
            .filter(|b| {
                // every valid ascii character
                (0x20..=0x7E).contains(b)
            })
            .collect()
    }
    /// Writes an absolute 64-bit jump instruction at the specified address.
    ///
    /// # Arguments
    /// - `address`: The memory address where the jump will be placed.
    /// - `destination`: The target address the jump will redirect to.
    ///
    /// # Returns
    /// - `Ok(true)`: If the jump was successfully written.
    /// - `Err(std::io::Error)`: If memory operations failed.
    ///
    /// # Description
    /// This function writes a 12-byte absolute jump instruction sequence:
    /// 1. `mov rax, destination` (10 bytes)
    /// 2. `jmp rax` (2 bytes)
    ///
    /// # Safety
    /// - Requires write permissions to target memory
    /// - Overwrites 12 bytes at the target address
    /// - Caller must ensure the address is valid and properly aligned
    ///
    /// # Memory Layout
    ///
    /// ```text
    /// [Before Hook]
    /// Address        Contents               Disassembly
    /// ────────────   ────────────────────   ────────────────────────
    /// 0x10000000     [Original Instruction] mov edi, 0x1234
    /// 0x10000005     [Original Instruction] call 0x20000000
    ///
    /// [After Hook]
    /// Address        Contents (hex)         Disassembly
    /// ────────────   ────────────────────   ────────────────────────
    /// 0x10000000     48 B8                  mov rax, 0x30000000
    /// 0x10000002     00 00 00 30 00 00 00 00
    /// 0x1000000A     FF E0                  jmp rax
    ///
    /// [Technical Breakdown]
    /// Offset  Size    Description
    /// ──────  ──────  ──────────────────────────────────────────────
    /// +0      2       MOV RAX opcodes (0x48 0xB8)
    /// +2      8       64-bit absolute destination address (little-endian)
    /// +10     2       JMP RAX opcodes (0xFF 0xE0)
    ///
    /// Total: 12 bytes of machine code
    /// ```
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(12345);
    /// process.place_absolute_jmp(0x10000000, 0x20000000)?;
    /// // Now calls to 0x10000000 will jump to 0x20000000
    /// ```
    pub fn place_absolute_jmp(&self, address: usize, destination: usize) -> Result<bool, Error> {
        unsafe {
            let handle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, self.pid);
            if handle.is_null() {
                return Err(Error::last_os_error())
            }

            // mov rax, imm64
            let mut patch: Vec<u8> = vec![0x48, 0xB8];
            patch.extend_from_slice(&(destination as u64).to_le_bytes());

            // jmp rax
            patch.extend_from_slice(&[0xFF, 0xE0]);

            let mut old_protect = 0;
            VirtualProtectEx(handle, address as LPVOID, patch.len(), PAGE_EXECUTE_READWRITE, &mut old_protect);

            let mut written = 0;
            let success = WriteProcessMemory(
                handle,
                address as LPVOID,
                patch.as_ptr() as LPCVOID,
                patch.len(),
                &mut written,
            );

            VirtualProtectEx(handle, address as LPVOID, patch.len(), old_protect, &mut 0);
            CloseHandle(handle);

            if success == 0 || written != patch.len() {
                return Err(Error::last_os_error())
            }

            Ok(success != 0)
        }
    }

    /// Allocates a specific amount of size in the target process and returns the allocated address.
    ///
    /// # Arguments:
    /// - `size`: The amount of size you want to allocate
    ///
    /// # Returns
    /// - `Ok(*mut u8)`: The allocated address
    /// - `std::io::error`: If the allocation failed
    ///
    /// # Must knows
    /// This function requires specific permissions (`PROCESS_VM_READ`, `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`) and you may
    /// need to see if you have those.
    pub fn allocate(&self, size: usize) -> Result<*mut u8, Error> {
        unsafe {
            let handle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 0, self.pid);
            if handle.is_null() {
                return Err(Error::last_os_error());
            }

            let allocated = VirtualAllocEx(
                handle,
                ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            );

            if allocated.is_null() {
                CloseHandle(handle);
                return Err(Error::last_os_error());
            }

            CloseHandle(handle);
            Ok(allocated as *mut u8)
        }
    }

    /// Places a trampoline hook at the specified `target_address`, redirecting executing to `hook_address`.
    ///
    /// # Arguments
    /// - `target_address`: The memory address of the function to hook.
    /// - `hook_address`: The memory address of your custom hook code.
    /// - `hook_length`: The number of bytes to overwrite in the original function (must be ≥ 12).
    ///
    /// # Returns
    /// - `Ok(*const u8)`: A pointer to the trampoline, which holds the original instructions followed by a jump back to the function body.
    /// - `Err(std::io::Error)`: If protecting, writing, etc. failed
    ///
    /// # Description
    /// This function creates a trampoline hook by:
    /// 1. Copying the first `hook_length` bytes of the original function.
    /// 2. Placing those bytes into a newly allocated trampoline buffer in the remote process.
    /// 3. Appending a `jmp` instruction at the end of the trampoline to resume execution after the overwritten section.
    /// 4. Overwriting the beginning of the original function with `mov rax, hook_address` + `jmp rax` instruction (12 bytes total).
    ///
    /// # Memory layout
    /// ```text
    /// [Original Function]
    /// Address        Contents               Disassembly
    /// ────────────   ────────────────────   ────────────────────────
    /// 0x10000000     [Original Instruction] mov eax, 1
    /// 0x10000005     [Original Instruction] call 0x20000000
    /// 0x1000000A     [Original Instruction] ...
    ///
    /// ↓↓↓ hook_length = 12 ↓↓↓
    ///
    /// [After Hooking]
    /// Address        Contents (hex)         Disassembly
    /// ────────────   ────────────────────   ────────────────────────
    /// 0x10000000     48 B8                  mov rax, hook_address
    /// 0x10000002     [hook_addr_bytes]      (8-byte hook address)
    /// 0x1000000A     FF E0                   jmp rax
    ///
    /// [Trampoline Allocated Memory]
    /// Address        Contents               Disassembly
    /// ────────────   ────────────────────   ────────────────────────
    /// 0x50000000     [Original Instruction] mov eax, 1
    /// 0x50000005     [Original Instruction] call 0x20000000
    /// 0x5000000A     48 B8                  mov rax, 0x1000000C
    /// 0x5000000C     0C 00 00 10 00 00 00 00 (8-byte return address)
    /// 0x50000014     FF E0                   jmp rax
    ///
    /// [Technical Breakdown]
    /// Offset  Size    Description
    /// ──────  ──────  ──────────────────────────────────────────────
    /// +0      10      MOV RAX + 64-bit absolute address (hook address)
    /// +10     2       JMP RAX opcodes (0xFF 0xE0)
    ///
    /// [Trampoline Breakdown]
    /// Offset  Size    Description
    /// ──────  ──────  ──────────────────────────────────────────────
    /// +0      5      Original instruction (mov eax, 1)
    /// +5      5      Original instruction (call 0x20000000)
    /// +A      10     MOV RAX + 64-bit return address (0x1000000C)
    /// +14     2      JMP RAX opcodes (0xFF 0xE0)
    /// ```
    /// # Safety
    /// - The caller must ensure that `hook_length` fully covers valid instructions (not in the middle of one).
    /// - This function operates on remote process memory and requires sufficient permissions.
    /// - Incorrect usage may cause crashes or undefined behaviour in the target process.
    ///
    /// # Example: Hook a function with ShellCode
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(12345);
    /// let target_function: usize = 0x10000000;
    /// // Number of bytes to overwrite — must be >= 12 (10 for mov rax, 2 for jmp rax)
    /// let hook_len = 12;
    ///
    /// let shellcode: [u8; 16] = [
    ///  0x90, 0x90, 0x90, 0x90,        // NOPs
    ///  0x48, 0xB8,                    // mov rax, trampoline_addr
    ///  0, 0, 0, 0, 0, 0, 0, 0,        // placeholder
    ///  0xFF, 0xE0,                     // jmp rax
    /// ];
    ///
    /// let shellcode_addr = process.allocate(shellcode.len()).unwrap() as usize;
    /// process.write_memory(
    ///     shellcode_addr,
    ///     &shellcode
    /// ).unwrap(); // write initial shellcode (With zero placeholder)
    ///
    /// let trampoline = process.trampoline_hook(target_function, shellcode_addr, hook_len).unwrap();
    /// // Update shellcode with actual trampoline address
    /// process.write_memory(
    ///     shellcode_addr + 6, // Skip 6 bytes (4 NOPs + 2 opcode bytes)
    ///     &trampoline.to_le_bytes() // Write 8-byte address
    /// ).unwrap();
    /// // Now when target_function is called:
    /// // 1. It jumps to shellcode_addr
    /// // 2. Shellcode moves trampoline_addr into RAX
    /// // 3. Jumps to trampoline
    /// // 4. Trampoline runs original code + jumps back
    ///```
    pub fn trampoline_hook(&self, target_address: usize, hook_address: usize, hook_length: usize) -> Result<*const u8, Error> {
        unsafe {
            let handle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, self.pid);
            if handle.is_null() {
                return Err(Error::last_os_error());
            }

            // Allocate enough for original bytes + 12 bytes for jump back (mov rax + jmp rax)
            // trampoline = [original bytes] + [mov rax, return_addr] + [jmp rax]
            let trampoline_size = hook_length + 12;
            let trampoline = VirtualAllocEx(
                handle,
                ptr::null_mut(),
                trampoline_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READ
            );

            if trampoline.is_null() {
                CloseHandle(handle);
                return Err(Error::last_os_error());
            }

            let mut original_bytes = Vec::<u8>::new();
            original_bytes.set_len(hook_length);
            {
                let src = target_address as *const u8;
                for i in 0..hook_length {
                    original_bytes[i] = *src.add(i);
                }
            }

            let mut written = 0;
            let success = WriteProcessMemory(
                handle,
                trampoline,
                original_bytes.as_ptr() as _,
                hook_length,
                &mut written
            );

            if success == 0 || written != hook_length {
                VirtualFreeEx(handle, trampoline, 0, MEM_RELEASE);
                CloseHandle(handle);
                return Err(Error::new(ErrorKind::Other, "WriteProcessMemory failed."));
            }

            let jump_back_addr = target_address + hook_length;
            let jump_back_ptr = (trampoline as usize + hook_length) as *mut u8;

            // mov rax, imm64 (10 bytes)
            let mut jump_back_patch: Vec<u8> = vec![0x48, 0xB8];
            jump_back_patch.extend_from_slice(&(jump_back_addr as u64).to_le_bytes());
            // jmp rax (2 bytes)
            jump_back_patch.extend_from_slice(&[0xFF, 0xE0]);

            let success = WriteProcessMemory(
                handle,
                jump_back_ptr as _,
                jump_back_patch.as_ptr() as _,
                jump_back_patch.len(),
                &mut written,
            );

            if success == 0 || written != jump_back_patch.len() {
                VirtualFreeEx(handle, trampoline, 0, MEM_RELEASE);
                CloseHandle(handle);
                return Err(Error::new(ErrorKind::Other, "WriteProcessMemory failed."));
            }

            // Create the detour patch that redirects execution from the target to the hook
            // mov rax, imm64 (10 bytes)
            let mut patch: Vec<u8> = vec![0x48, 0xB8];
            patch.extend_from_slice(&(hook_address as u64).to_le_bytes());
            // jmp rax (2 bytes)
            patch.extend_from_slice(&[0xFF, 0xE0]);

            let mut old_protect = 0;
            let success = VirtualProtectEx(
                handle,
                target_address as LPVOID,
                patch.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );

            if success == 0 {
                CloseHandle(handle);
                return Err(Error::last_os_error());
            }

            let success = WriteProcessMemory(
                handle,
                target_address as LPVOID,
                patch.as_ptr() as LPCVOID,
                patch.len(),
                &mut written
            );
            let mut new_old_protect = 0;
            VirtualProtectEx(handle, target_address as LPVOID, patch.len(), old_protect, &mut new_old_protect);

            CloseHandle(handle);
            if success == 0 || written != patch.len() {
                VirtualFreeEx(handle, trampoline, 0, MEM_RELEASE);
                return Err(Error::new(ErrorKind::Other, "WriteProcessMemory failed."));
            }

            Ok(trampoline as *const u8)
        }
    }

    /// Retrieves information about all modules loaded in the target process.
    ///
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<ModuleInfo>)` - A vector of all the modules
    /// * `Err(std::io::Error)` - if an error occurs during the search.
    ///
    /// # Safety
    /// This function uses unsafe Windows API calls and should be used with caution in trusted code contexts.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// # use memory_utils::process::ModuleInfo;
    /// let process = Process::new(1234);
    /// let modules = process.get_modules()?;
    /// for module in modules {
    ///     println!("{}", module.name);
    /// }
    /// ```
    pub fn get_modules(&self) -> Result<Vec<ModuleInfo>, Error> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(Error::last_os_error());
            }

            let mut entry: MODULEENTRY32 = zeroed();
            entry.dwSize = size_of::<MODULEENTRY32>() as u32;

            if Module32First(snapshot, &mut entry) == 0 {
                CloseHandle(snapshot);
                return Err(Error::last_os_error());
            }
            let mut result = Vec::<ModuleInfo>::new();

            loop {
                let name_cstr = CStr::from_ptr(entry.szModule.as_ptr());
                let name = name_cstr.to_string_lossy().into_owned();

                result.push(ModuleInfo {
                    base_address: entry.hModule as *mut _,
                    entry,
                    name
                });


                if Module32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }

            CloseHandle(snapshot);
            Ok(result)
        }

    }

    /// Parses the Portable Executable (PE) headers and section table from a given base memory address.
    ///
    /// This function reads the DOS header, NT headers, and section headers from a PE file loaded in memory (e.g., a module in
    /// a remote process or a file mapped to memory). It returns a [`PeInfo`] struct containing the parsed data about the executable.
    ///
    /// # Parameters
    /// - `base_address`: A raw pointer to the base address of the PE file in memory.
    ///                   This must point to a valid PE image (typically the module base of a loaded binary).
    ///
    /// - `sanitize_sections`: If `true`, the function will sanitize the raw contents of each PE section,
    ///                        removing null bytes (`0x00`) and non-printable characters from the output.
    ///                        This is useful for improving readability when logging or displaying section
    ///                        contents to the user. If `false`, the section contents are returned as-is,
    ///                        preserving all raw bytes.
    ///
    /// # Returns
    ///
    /// * [`PeInfo`] - A struct, containing must info, if the process succeeded
    /// * `Err(std::io::Error)` - if the base address does not point to valid PE structure or the memory is unreadable.
    ///
    /// # Behaviour
    ///
    /// - The function verifies `MZ` and `PE\0\0` signatures.
    /// - It reads and parses headers including the DOS headers, NT headers,
    ///   optional headers, and section headers.
    /// - For each section, it reads section names, sizes, virtual addresses, and raw data.
    /// - If `sanitize_sections` is true,  the raw data of each section is cleaned up by:
    ///     - Removing non-printable ASCII character (those not in `0x20..=0x7E`)
    ///     - Stripping null bytes and control characters.
    ///     - Example: `H�\$H�t$H�|$UH�l$�H��� ` -> `H$Ht$H|$UHl$H`
    ///
    /// # Use Case
    /// Use `sanitize_sections = true` when:
    /// - You're generating readable reports or exporting data for human inspeciton.
    /// - You want to detect human-readable strings embedded in sections.
    ///
    /// Use `sanitize_sections = false` when:
    /// - Performing exact byte-level operations (hashing, patching).
    /// - Analyzing encrpyted/packed sections that rely on full byte fidelity.
    ///
    /// # Safety
    ///
    /// This function dereferences raw pointers and assumes the given base address
    /// points to a valid mapped memory region. Undefined behaviour may occur if the
    /// pointer is invalid or if the memory is unmapped.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process_id = Process::pid("RobloxPlayerBeta.exe").unwrap();
    /// let process = Process::new(process_id);
    ///
    /// let module = process.get_module("RobloxPlayerBeta.dll").unwrap();
    /// let base = module.base_address as *mut u8;
    /// // sanitize output
    /// let headers = process.pe_headers(base, true).unwrap();
    /// let sections = headers.sections;
    /// println!("{:#?}", sections);
    ///
    /// let exports = headers.exports;
    /// if let Some(export) = exports {
    ///     let info = export.export_info;
    ///     let addresses = info.AddressOfFunctions as usize;
    ///     let export_directory_address = export.export_directory_address as usize;
    ///
    ///     println!("{}", export_directory_address);
    ///     println!("{}", addresses);
    /// }
    /// ```
    pub fn pe_headers(&self, base_address: *mut u8, sanitize_sections: bool) -> Result<PeInfo, Error>  {
        unsafe {
            // Reading PE Headers from Remote Process
            let mut dos_headers: IMAGE_DOS_HEADER = zeroed();
            let base_address = base_address as usize;

            let process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, self.pid);
            if process.is_null() {
                return Err(Error::last_os_error());
            }
            let success = ReadProcessMemory(
                process,
                base_address as LPCVOID,
                &mut dos_headers as *mut _ as LPVOID,
                size_of::<IMAGE_DOS_HEADER>(),
                ptr::null_mut()
            );

            if success == 0 {
                CloseHandle(process);
                return Err(Error::last_os_error());
            }

            // If a file doesn't begin with "MZ" (0x5A4D), it is not a valid PE file, and trying to parse further (e.g. jumping to e_lfanew)
            // would be dangerous and could cause a crash or garbage results.
            if dos_headers.e_magic != 0x5A4D {
                CloseHandle(process);
                return Err(Error::new(ErrorKind::InvalidData, format!("Invalid DOS header: {}", dos_headers.e_magic)));
            }

            // e_lfanew points to the NT header.
            let nt_header_addr = base_address + dos_headers.e_lfanew as usize;
            let mut nt_headers: IMAGE_NT_HEADERS64 = zeroed();

            let success = ReadProcessMemory(
                process,
                nt_header_addr as LPCVOID,
                &mut nt_headers as *mut _ as LPVOID,
                size_of::<IMAGE_NT_HEADERS64>(),
                ptr::null_mut()
            );

            if success == 0 {
                CloseHandle(process);
                return Err(Error::last_os_error());
            }

            // 0x00004550 (PE\0\0) is the signature of the IMAGE_NT_HEADERS, which marks the start of the main PE header in a Windows binary.
            if nt_headers.Signature != 0x00004550 {
                CloseHandle(process);
                return Err(Error::new(ErrorKind::InvalidData, format!("Invalid PE signature: {}", nt_headers.Signature)));
            }

            // -------------------------------------------------------------------------------------------------------------------------------- \\

            // Parse Section Headers
            let section_header_addr = nt_header_addr + size_of::<IMAGE_NT_HEADERS64>();
            let num_section = nt_headers.FileHeader.NumberOfSections as usize;

            let mut sections = Vec::new();

            for i in 0..num_section {
                let mut section: IMAGE_SECTION_HEADER = zeroed();
                let success = ReadProcessMemory(
                    process,
                    ( section_header_addr + i * size_of::<IMAGE_SECTION_HEADER>() ) as LPCVOID,
                    &mut section as *mut _ as LPVOID,
                    size_of::<IMAGE_SECTION_HEADER>(),
                    ptr::null_mut()
                );

                if success == 0 {
                    continue
                }

                let name = String::from_utf8_lossy(&section.Name)
                    .trim_matches('\0')
                    .to_string();

                let section_base = base_address + section.VirtualAddress as usize;
                let section_size = unsafe { *section.Misc.VirtualSize() as usize };

                if section_size == 0 {
                    continue
                }

                let mut buffer = Vec::with_capacity(section_size);
                buffer.set_len(section_size);

                let success = ReadProcessMemory(
                    process,
                    section_base as LPCVOID,
                    buffer.as_mut_ptr() as LPVOID,
                    section_size,
                    ptr::null_mut()
                );

                if success == 0 {
                    continue
                }

                let clean_name = name.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect::<String>();
                let path = format!("dump_{}.bin", clean_name);

                let cleaned_data = if sanitize_sections {
                    self.sanitize_bytes(&buffer)
                } else {
                    buffer
                };

                fs::write(&path, &cleaned_data)?;

                sections.push( SectionInfo {
                    name,
                    virtual_address: section_base as LPVOID,
                    virtual_size: section_size,
                    dumped_path: path
                })
            };

            // -------------------------------------------------------------------------------------------------------------------------------- \\

            // Parsing the Export table
            let export_dir_rva = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;

            let export_info = if export_dir_rva != 0 {
                let mut export_dir: IMAGE_EXPORT_DIRECTORY = zeroed();
                let export_dir_addr = base_address + export_dir_rva as usize;
                let success = ReadProcessMemory(
                    process,
                    export_dir_addr as LPCVOID,
                    &mut export_dir as *mut _ as LPVOID,
                    size_of::<IMAGE_EXPORT_DIRECTORY>(),
                    ptr::null_mut()
                );



                Some( ExportInfo {
                    export_info: export_dir,
                    export_directory_address: export_dir_addr as LPVOID
                } )
            } else {
                None
            };

            CloseHandle(process);

            Ok(PeInfo {
                sections,
                exports: export_info
            })
        }
    }


    /// Queries the memory protection of a specific address in the target process.
    ///
    /// This function opens the target process with the required permissions and uses
    /// `VirtualQueryEx` to retrieve memory protection attributes (such as `PAGE_READWRITE`,
    /// `PAGE_EXECUTE`, etc.) of the memory that includes the given address.
    ///
    /// # Arguments
    ///
    /// * `address` - The memory address in the remote process to query.
    ///
    /// # Returns
    /// * `Ok(ProtectOptions)` -  if the protection was successfully retrieved.
    /// * `Err(std::io::Error)` - if the process could not be opened or the query failed.
    ///
    /// # Safety
    /// This function performs Windows API calls and works with raw pointers. It assumes that the address
    /// provided is valid within the target process's address space.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(1234);
    /// let protection = process.get_protection(0x12345678)?;
    /// println!("Found base address: {:?}", protection)
    /// ```
    pub fn get_protection(&self, address: usize) -> Result<ProtectOptions, Error> {
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, self.pid);
            if process.is_null() {
                return Err(Error::last_os_error());
            }

            let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
            let success = VirtualQueryEx(
                process,
                address as LPCVOID,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>()
            );

            if success == 0 {
                CloseHandle(process);
                return Err(Error::last_os_error());
            }

            CloseHandle(process);
            Ok(ProtectOptions::from(mbi.Protect))
        }
    }

    /// Returns the base address of the main module (i.e, the executable) of a process by its PID.
    ///
    /// This scans the module list of the process using Toolhelp32 and returns the base address
    /// (`hModule`) of the first module found - which is the main executable module.
    ///
    /// # Returns
    /// * `Ok(*mut u8)` - The base address of the executable module
    /// * `Err(std::io::Error)` - If the snapshot or module iteration fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(1234);
    /// let base = process.get_base_address()?;
    /// println!("Found base address: {:?}", base)
    /// ```
    pub fn get_base_address(&self) -> Result<*mut u8, Error> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE  | TH32CS_SNAPMODULE32, self.pid);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(Error::last_os_error());
            }

            let mut entry: MODULEENTRY32 = zeroed();
            entry.dwSize = size_of::<MODULEENTRY32>() as u32;

            if Module32First(snapshot, &mut entry) == 0 {
                CloseHandle(snapshot);
                return Err(Error::last_os_error());
            }

            CloseHandle(snapshot);
            Ok(entry.hModule as *mut u8)
        }
    }



    /// This terminates the current process.
    ///
    /// # Arguments
    /// * `exit_code` - The exit code you want to exit with. If none is provided it will default to `1`
    ///
    pub fn terminate(&self, exit_code: Option<u32>) -> Result<(), Error> {
        unsafe  {
            let handle = OpenProcess(PROCESS_TERMINATE, 0, self.pid);
            if handle.is_null() {
                return Err(Error::last_os_error());
            }

            let success = TerminateProcess(handle, exit_code.unwrap_or(1));
            CloseHandle(handle);

            if success == 0 {
                return Err(Error::last_os_error());
            }

            Ok(())
        }
    }

    /// Retrieves information about a specific module loaded in the target process.
    ///
    /// This function searches the modules loaded in the process identified by `self.pid`,
    /// matching the given `module_name` (case-insensitive). If found it return a `ModuleInfo`
    /// struct containing the module's base address, full `MODULEENTRY32` data, and the name.
    ///
    /// # Arguments
    /// * `module_name` - The name of the module to search for, e.g., `"client.dll"`
    ///
    /// # Returns
    ///
    /// * `Ok(ModuleInfo)` if the module is found
    /// * `Err(std::io::Error)` if the module is not found or an error occurs during the search.
    ///
    /// # Safety
    /// This function uses unsafe Windows API calls and should be used with caution in trusted code contexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use memory_utils::process::Process;
    /// # use memory_utils::process::ModuleInfo;
    /// let process = Process::new(1234);
    /// let module = process.get_module("client.dll")?;
    /// println!("client.dll base address: {:?}", module.base_address);
    /// ```
    pub fn get_module(&self, module_name: &str) -> Result<ModuleInfo, Error> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(Error::last_os_error());
            }

            let mut entry: MODULEENTRY32 = zeroed();
            entry.dwSize = size_of::<MODULEENTRY32>() as u32;

            if Module32First(snapshot, &mut entry) == 0 {
                CloseHandle(snapshot);
                return Err(Error::last_os_error());
            }

            loop {
                let name_cstr = CStr::from_ptr(entry.szModule.as_ptr());
                let name = name_cstr.to_string_lossy().into_owned();

                if name.eq_ignore_ascii_case(module_name) {
                    CloseHandle(snapshot);
                    return Ok(ModuleInfo {
                        base_address: entry.hModule as *mut _,
                        entry,
                        name
                    })
                }

                if Module32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }

            CloseHandle(snapshot);
            Err(Error::new(ErrorKind::NotFound, "Module not found"))
        }
    }




    /// Get the PID of a process by its executable name (e.g., "obs64.exe").
    ///
    /// # Arguments
    /// * `name` - The name of the executable you want to find.
    ///
    /// # Returns
    /// * `Ok(pid)` - If the PID was found.
    /// * `Err(std::io::Error)` - If the process isn't found or a system error occurred.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let pid = Process::pid("obs64.exe").expect("Error while trying to retrieve the PID");
    /// let process = Process::new(pid);
    /// ```
    pub fn pid(name: &str) -> Result<u32, Error> {
        unsafe  {

            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(Error::last_os_error());
            }

            let mut entry: PROCESSENTRY32 = zeroed();
            entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

            if Process32First(snapshot, &mut entry) == 0 {
                CloseHandle(snapshot);
                return Err(Error::last_os_error());
            }

            loop {
                let exe_name = CStr::from_ptr(entry.szExeFile.as_ptr())
                    .to_string_lossy()
                    .into_owned();

                if exe_name.eq_ignore_ascii_case(name) {
                    CloseHandle(snapshot);
                    return Ok(entry.th32ProcessID);
                }

                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }

            CloseHandle(snapshot);
            Err(Error::new(ErrorKind::NotFound, "Process not found"))
        }
    }

    /// Retrieves the CPU context (registers) of a specific thread in the target process.
    ///
    /// # Parameters
    /// - `thread_id`: The thread ID (TID) of the target thread.
    ///
    /// # Returns
    /// - `Ok(CONTEXT)` on success, containing the full CPU context of the thread.
    ///- `Err(std::io::Error)` if the thread does not exist, cannot be opened, or [`GetThreadContext`] fails.
    ///
    /// # Safety
    /// This function directly interacts with thread-level Windows APIs and retrieves register state.
    /// Use only when you need low-level debugging, manipulation, or memory tracing.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(1234);
    /// let context = process.get_thread_context(12345).expect("Failed to get thread context");
    /// println!("Rax: {:#X}", context.Rax)
    /// ```
    pub fn get_thread_context(&self, thread_id: u32) -> Result<CONTEXT, Error> {
        unsafe {
            let thread_exists = self.thread_exists(thread_id); // if thread doesn't exist this will error
            if thread_exists.is_err() {
                return Err(Error::last_os_error());
            }
            let thread = OpenThread(THREAD_GET_CONTEXT, 0, thread_id);
            if thread.is_null() {
                return Err(Error::last_os_error());
            }

            let mut context: CONTEXT = zeroed();
            context.ContextFlags = CONTEXT_ALL;

            let success = GetThreadContext(thread, &mut context) != 0;
            CloseHandle(thread);

            if !success {
                return Err(Error::last_os_error());
            }

            Ok(context)
        }
    }

    /// This function uses `process.read_memory` and returns the result as a
    /// boolean. If you want to see what it exactly does please look at the
    /// `process.read_memory` documentation.
    pub fn read_bool(&self, address: usize) -> Result<bool, Error> {
        self.read_memory::<bool>(address)
    }

    /// This function uses `process.read_memory` and returns the result as a
    /// [`LONG`] (`i32`). If you want to see what it exactly does please look at the
    /// `process.read_memory` documentation.
    ///
    ///
    pub fn read_long(&self, address: usize) -> Result<LONG, Error> {
        self.read_memory::<LONG>(address)
    }

    /// This function uses `process.read_memory` and returns the result as a
    /// [`LONGLONG`] (`i64`). If you want to see what it exactly does please look at the
    /// `process.read_memory` documentation.
    pub fn read_longlong(&self, address: usize) -> Result<LONGLONG, Error> {
        self.read_memory::<LONGLONG>(address)
    }

    /// Reads a null-terminated UTF-8 string from another process's memory.
    ///
    /// # How?
    ///
    /// This function reads memory byte-by-byte starting at the specified address
    /// until it encounters a null terminator (`\0`). It is useful for reading C-style
    /// string from memory without needing to specify the length.
    ///
    /// # Parameters
    ///
    /// - `address`: THe base address in the target process where the string begins.
    ///
    /// # Returns
    ///
    /// - `Ok(String)` containing the string that was read, if successful.
    /// - `Err(std::io::Error)` if the process cannot be opened, memory cannot be read,
    ///    or the string is not valid UTF-8
    ///
    /// # Safety
    ///
    /// This function performs raw pointer operations and reads another process' memory,
    /// which can be unsafe if the memory is inaccessible or invalid.
    ///
    /// # Limitations
    /// - This function imposes a safety cap of 4096 bytes. If no null terminator is found
    ///   within that limit, the function returns an error.
    /// - The string must be valid UTF-8. Invalid byte sequences will cause an error.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(1234);
    /// let address = 0x7FFDEAD000u64 as usize;
    /// match process.read_string(address) {
    ///      Ok(string) => println!("Read string: {}", string),
    ///         Err(e) => eprintln!("Failed to read string: {}", e),
    /// }
    /// ```
    pub fn read_string(&self, address: usize) -> Result<String, Error> {
        unsafe {
            let mut buffer = Vec::new();
            let mut offset = 0;

            loop {
                let mut byte: u8 = 0;
                let success = ReadProcessMemory(
                    self.handle,
                    (address + offset) as LPCVOID,
                    &mut byte as *mut _ as LPVOID,
                    1,
                    ptr::null_mut(),
                );

                if success == 0 {
                    return Err(Error::last_os_error());
                }

                if byte == 0 { // null-terminator found
                    break;
                }

                buffer.push(byte);
                offset += 1;

                if offset > 4096 {
                    return Err(Error::new(ErrorKind::InvalidData, "String too long or not null-terminated"))
                }
            }

            String::from_utf8(buffer).map_err(|e| Error::new(ErrorKind::InvalidData, e))

        }
    }

    /// Reads a portion of the stack memory of the specified thread.
    ///
    /// # How?
    /// This function uses [`OpenThread`] to obtain a handle to the specified thread, retrieves the thread context
    /// using [`GetThreadContext`], and calculates the stack address using the `Rsp` register. It then reads a total
    /// of `size_l + size_r` bytes from around the tack pointer using [`ReadProcessMemory`] and returns the resulting
    /// memory as a [`Stack`] or `Err(std::io::Error)` if the operation didn't succeed.
    ///
    /// # Parameters
    /// - `thread_id`: The thread ID (`u32`) of the target thread whose stack should be read.
    /// - `size_l`: The number of bytes to read before the current stack pointer (`RSP`). This is useful
    /// for examining the stack leading up to the current call frame.
    /// - `size_r`: The number of bytes to read after the current stack pointer.
    ///
    /// # Returns
    ///
    /// - `Ok(Stack)`: A struct that contains the buffer, the stack pointer, the base address and the stack size.
    /// - `Err(std::io::Error)`: If opening the thread, retrieving the thread context, or reading memory fails.
    ///
    /// # Safety
    ///
    /// This function uses multiple unsafe Windows API calls (`OpenThread`, `GetThreadContext`, `ReadProcessMemory`)
    /// and must be used with caution. Improper usage may lead to undefined behaviour or system instability.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(1234);
    /// let thread_id = 5678;
    /// let stack_data = process.read_stack(thread_id, 128, 128)
    ///                     .expect("Failed to read stack");
    /// println!("{:?}", stack_data);
    /// ```
    pub fn read_stack(&self, thread_id: u32, size_l: usize, size_r: usize) -> Result<Stack, Error> {
        unsafe {
            let thread_exists = self.thread_exists(thread_id);
            if thread_exists.is_err() {
                return Err(Error::last_os_error());
            }

            let thread: HANDLE = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, 0, thread_id);
            if thread.is_null() {
                return Err(Error::last_os_error());
            }

            let mut context: CONTEXT = zeroed();
            context.ContextFlags = CONTEXT_ALL;

            if GetThreadContext(thread, &mut context) == 0 {
                CloseHandle(thread);
                return Err(Error::last_os_error());
            }

            let stack_ptr = context.Rsp as usize;
            let start_addr = stack_ptr.saturating_sub(size_l);
            let total_size = size_l + size_r;

            let mut buffer = Vec::with_capacity(total_size);
            buffer.set_len(total_size);

            let mut bytes_read = 0;



            let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
            VirtualQueryEx(
                self.handle,
                stack_ptr as LPCVOID,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            let stack_base = mbi.BaseAddress as LPVOID;
            let stack_size = mbi.RegionSize as usize;

            let success = ReadProcessMemory(
                self.handle,
                start_addr as LPVOID,
                buffer.as_mut_ptr() as LPVOID,
                total_size,
                &mut bytes_read
            );
            CloseHandle(thread);

            if success == 0 {
                return Err(Error::last_os_error())
            } else {
                buffer.truncate(bytes_read);
                let stack_ptr = stack_ptr as LPCVOID;
                Ok(Stack {
                    buffer,
                    stack_ptr,
                    stack_size,
                    base_address: stack_base
                })
            }
        }
    }

    /// Checks whether a memory address is valid and accessible in the target process.
    ///
    /// This method uses `VirtualQueryEx` to determine if a given memory address is
    /// within a valid and committed region of the remote process. This is useful
    /// when you want to ensure that an address can be safely read or written to
    /// without causing an access violation.
    ///
    /// # Parameters
    ///
    /// - `address`: The memory address to check, as a `usize`.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the address is valid and information was successfully queried.
    /// - `Ok(false)` if the address is not valid (i.e., no memory region mapped).
    /// - `Err(std::io::Error)` if the process handle could not be opened or the query failed.
    ///
    /// # Example
    ///
    /// ```
    /// # use memory_utils::process::Process;
    /// let process = Process::new(12345);
    /// let address = 0x10000000;
    /// match process.is_valid_address(address) {
    ///     Ok(true) => println!("Address is valid!"),
    ///     Ok(false) => println!("Address is not valid."),
    ///     Err(e) => println!("Failed to query address: {}", e),
    /// }
    /// ```
    ///
    /// # Safety
    ///
    /// This function performs an unsafe system call and requires correct usage
    /// of process memory APIs. Improper use may cause undefined behavior.
    pub fn is_valid_address(&self, address: usize) -> Result<bool, Error> {
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
            let success = VirtualQueryEx(
                self.handle,
                address as LPCVOID,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            Ok(success != 0)
        }
    }

    /// Converts a [`ProtectOptions`] variant into the corresponding `u32` memory protection constant
    /// used by the Windows API (e.g, [`PAGE_READONLY`], [`PAGE_READWRITE`], etc.)
    ///
    /// It returns the old protection.
    /// # Conversion Table
    ///
    /// | Variant       | Corresponding Constant  |
    /// |---------------|-------------------------|
    /// | `NoAccess`    | `PAGE_NOACCESS`         |
    /// | `ReadOnly`    | `PAGE_READONLY`         |
    /// | `ReadWrite`   | `PAGE_READWRITE`        |
    /// | `ExecuteRead` | `PAGE_EXECUTE_READ`     |
    ///
    /// And all the others supported
    ///
    /// # Safety
    /// While this conversion itself is safe, the resulting value is typically passed into unsafe
    /// Windows API calls like [`VirtualProtect`], which can cause undefined behaviour or crashes
    /// if used incorrectly (e.g, on invalid memory regions)
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// # use memory_utils::process::ProtectOptions;
    /// let process = Process::new(1234);
    /// let address = 0x7FFDEADBEEF;
    /// let size: usize = 4096;
    /// let protection = ProtectOptions::NoAccess;
    ///
    /// match process.protect_memory(address, size, protection) {
    ///     Ok(_) => println!("Memory protection changed successfully."),
    ///     Err(e) => eprintln!("Failed to change memory protection: {:?}", e),
    /// }
    /// ```
    pub fn protect_memory(&self, address: usize, size: usize, new_protect: ProtectOptions) -> Result<ProtectOptions, Error> {
        unsafe {
            let mut old_protect: DWORD = 0;
            let result = VirtualProtectEx(
                self.handle,
                address as LPVOID,
                size,
                new_protect.into(),
                &mut old_protect
            );
            if result == 0 {
                return Err(Error::last_os_error());
            };

            Ok(ProtectOptions::from(old_protect))
        }


    }

    /// Reads memory of type `T` from another process given a PID and address.
    ///
    /// # Type Constrains
    ///
    /// - `T: Copy`
    ///    Ensures that the value can be safely duplicated using a bitwise copy.
    ///    This is required because the value is read from raw memory and must be copied
    ///    without invoking any custom logic like destructors or ownership semantics.
    ///
    /// - `T: Sized`
    ///   Guarantees that the compiler knows the size of `T` at compile time.
    ///   This is necessary to provide the exact byte size to `ReadProcessMemory`
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the process handle cannot be opened or reading memory fails.
    ///
    /// # Safety
    ///
    /// This function is unsafe internally because it calls Windows API functions
    /// that operate on raw pointers.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let reader = Process::new(1234);
    /// let address = 0x7FFDEADBEEF;
    /// let value: u32 = reader.read_memory(address).expect("Failed to read memory");
    /// println!("Read value: {}", value);
    /// ```
    pub fn read_memory<T: Copy + Sized>(&self, address: usize) -> Result<T, Error> {
        unsafe {
            let mut buffer: T = zeroed();
            let success = ReadProcessMemory(
                self.handle,
                address as LPCVOID,
                &mut buffer as *mut _ as LPVOID,
                size_of::<T>(),
                ptr::null_mut()
            );

            if success == 0 {
                return Err(Error::last_os_error());
            } else {
                Ok(buffer)
            }
        }
    }

    /// Writes a value of type `T` into another process's memory.
    ///
    /// # Type Constrains
    ///
    /// - `T: Copy`
    ///    Ensures that the value can be safely duplicated using a bitwise copy.
    ///    This is required because the value is read from raw memory and must be copied
    ///    without invoking any custom logic like destructors or ownership semantics.
    ///
    /// - `T: Sized`
    ///   Guarantees that the compiler knows the size of `T` at compile time.
    ///   This is necessary to provide the exact byte size to `WriteProcessMemory`
    ///
    /// # Parameters
    ///
    /// - `address`: Address in the target process where the value should be written.
    /// - `value`: Reference to the value to write
    ///
    /// # Returns
    /// - `Ok(())` on success.
    /// - [`Error`] if the process could not be opened or memory could not be written.
    ///
    /// # Safety
    ///
    /// This function performs raw pointer operations and writes into another process's
    /// memory space. Ensure that the `address` is valid and that the type `T` matches
    /// the expected layout at that address.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let writer = Process::new(1234);
    /// let address = 0x7FFDEADBEEF;
    /// let new_value: u32 = 1337;
    /// writer.write_memory(address, &new_value).expect("Failed to write memory");
    /// println!("Memory write succeeded")
    /// ```
    pub fn write_memory<T: Copy + Sized>(&self, address: usize, value: &T) -> Result<(), Error> {
        unsafe {
            let success = WriteProcessMemory(
                self.handle,
                address as LPVOID,
                value as *const _ as LPCVOID,
                size_of::<T>(),
                ptr::null_mut()
            );


            if success == 0 {
                return Err(Error::last_os_error());
            } else {
                Ok(())
            }
        }
    }
    /// Parses a pattern string like `"48 8B ?? 48"` into a byte vector and a mask.
    ///
    /// `x` in the mask indicates exact match, `?` is a wildcard.
    fn parse_pattern_string(&self, pattern_str: &str) -> (Vec<u8>, String) {
        let mut bytes = Vec::new();
        let mut mask = String::new();

        for token in pattern_str.split_whitespace() {
            if token == "?" || token == "??" {
                bytes.push(0x00); // Wildcard byte
                mask.push('?');     // Wildcard mask
            } else {
                let byte = u8::from_str_radix(token, 16).unwrap_or(0x00);
                bytes.push(byte);
                mask.push('x'); // Exact match mask
            }
        }

        (bytes, mask)
    }
    /// Searches a data buffer for a given byte pattern using a mask.
    /// Uses the Boyer-Moore-Horspool Algorithm
    pub fn find_pattern(&self, haystack: &[u8], pattern: &[u8], mask: &str ) -> Option<usize> {
        let pattern_len = pattern.len();
        if pattern_len == 0 || haystack.len() < pattern_len {
            return None;
        }

        let mut skip_table = [pattern_len; 256];

        for i in 0..(pattern_len - 1) {
            if mask.as_bytes()[i] == b'?' {
                continue;
            }
            skip_table[pattern[i] as usize] = pattern_len - i - 1;
        }

        let mut i = 0;
        while i <= haystack.len() - pattern_len {
            let mut j = (pattern_len - 1) as isize;
            while j >= 0 {
                let pj = j as usize;
                if mask.as_bytes()[pj] != b'?' && haystack[i + pj] != pattern[pj] {
                    break;
                }
                j -= 1;
            }

            if j < 0 {
                return Some(i);
            }

            i += skip_table[haystack[i + pattern_len - 1] as usize];
        }

        None
    }
    /// Scans the memory of a given process for a pattern using a mask.
    ///
    /// # How does it work?
    ///
    /// This functions walks through the virtual memory regions of a process,
    /// looking for a specific byte pattern. It filters memory regions based on
    /// state and protection (e.g., commited, writeable), then reads their content.
    /// The contents are compared against the provided pattern and mask, where:
    ///
    /// - `'x'` in the mask means the corresponding byte in the pattern must match exactly.
    /// - Any other character (commonly `'?'`) means the byte is treated as a wildcard.
    ///
    /// The scan stops as soon as a match is found.
    ///
    /// # Arguments
    ///
    /// * `pattern` - A byte slice representing the pattern to search for.
    /// * `mask` - A mask string corresponding to the pattern.
    ///
    /// # Returns
    ///
    /// `Ok(address)` if the pattern is  found, or an `Err` if not found or on error.
    ///
    /// # Safety
    /// This function performs raw memory reads using Windows APIs like `ReadProcessMemory`
    /// and must be used with caution. Ensure the process and regions accessed are safe
    /// to read from, or undefined behavior may occur (e.g., access violations).
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(1234);
    /// let pattern_vec: Vec<u8> = vec![0x48, 0x8B, 0xC4];
    /// let pattern: &[u8] = &pattern_vec;
    /// let mask = "xxx";
    /// let result = process.pattern_scan(&pattern, mask);
    /// ```
    pub fn pattern_scan(&self, pattern: &[u8], mask: &str) -> Result<usize, Error> {
        unsafe {
            let mut addr: usize = 0;
            let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();

            while VirtualQueryEx(self.handle, addr as LPCVOID, &mut mbi as *mut _, size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
                if mbi.State == MEM_COMMIT && (
                    mbi.Protect == PAGE_EXECUTE_READWRITE
                        || mbi.Protect ==  PAGE_READWRITE
                        || mbi.Protect == PAGE_READONLY ) &&
                    mbi.RegionSize > 0
                {
                    let mut buffer = vec![0u8; mbi.RegionSize];
                    let mut bytes_read = 0;

                    if ReadProcessMemory(
                        self.handle,
                        addr as LPCVOID,
                        buffer.as_mut_ptr() as LPVOID,
                        mbi.RegionSize,
                        &mut bytes_read,
                    ) != 0 {
                        if let Some(found) = self.find_pattern(&buffer, pattern, mask) {
                            return Ok(addr + found);
                        }
                    }
                }

                addr += mbi.RegionSize;
            }

            return Err(Error::new(ErrorKind::NotFound, "Pattern not found"));
        }

    }

    /// Convenience wrapper that accepts a human-readable pattern string.
    ///
    /// This converts a pattern like `"48 8B C4 ?? 89 50"` into a byte buffer and mask,
    /// and calls `pattern_scan`
    ///
    /// # Arguments
    ///
    /// * `pattern_str` - A pattern string with wildcards, e.g., `"48 8B ?? 48 89 50"`
    ///
    /// # Returns
    ///
    /// `Ok(address)` if found, otherwise an error.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(1234);
    /// let result = process.find_pattern_str("48 8B C4 48 89 50 ?? 4C 89");
    /// ```
    pub fn find_pattern_str(&self, pattern_str: &str) -> Result<usize, Error> {
        let (pattern, mask) = self.parse_pattern_string(pattern_str);
        self.pattern_scan(&pattern, &mask)
    }


    /// Suspends all threads of the target process.
    ///
    /// # How?
    /// This function takes the process ID stored in `self.pid` and iterates over all
    /// threads in the system. For each thread belonging to the target process, it opens
    /// a handle with `THREAD_SUSPEND_RESUME` access rights and calls `SuspendThread` to
    /// suspend its execution.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all threads were successfully suspended or if there were no threads.
    /// - `Err(std::io::Error)` if creating the snapshot or enumerating threads fails.
    ///
    /// # Safety
    ///
    /// This function performs unsafe Windows API calls including [`CreateToolhelp32Snapshot`],
    /// [`OpenThread`], and [`SuspendThread`]. It must be called with caution, as suspending
    /// threads can cause deadlocks or inconsitent program states.
    ///
    /// Suspending threads in a process may cause it to freeze or behave unexpectedly.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(1234);
    /// process.suspend().expect("Failed to suspend process");
    /// ```
    pub fn suspend(&self) -> Result<(), Error> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(Error::last_os_error());
            }

            let mut entry: THREADENTRY32 = zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut entry) == 0 {
                CloseHandle(snapshot);
                return Err(Error::last_os_error());
            };

            loop {
                if entry.th32OwnerProcessID == self.pid {
                    let thread: HANDLE = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                    if !thread.is_null() {
                        SuspendThread(thread);
                        CloseHandle(thread);
                    }
                }

                if Thread32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }

            CloseHandle(snapshot);
            Ok(())
        }
    }

    /// Resumes all threads of the target process.
    ///
    /// # How?
    ///
    /// This function takes a snapshot of all threads in the system using [`CreateToolhelp32Snapshot`] with [`TH32CS_SNAPPROCESS`],
    /// and iterates trough each one. If a thread belongs to the process specified by `self.pid`,
    /// it attempts to resume it using [`ResumeThread`].
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all threads were successfully resumed or if there were no threads.
    /// - `Err(std::io::Error)` if creating the snapshot or enumerating threads fails.
    ///
    /// # Safety
    ///
    /// This function performs unsafe Windows API calls including [`CreateToolhelp32Snapshot`],
    /// [`OpenThread`], and [`ResumeThread`] and must therefore be called with caution because
    /// it can lead to undefined behaviour or system instability if used incorrectly.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(1234);
    /// process.suspend().expect("Failed to suspend process");
    /// process.resume().expect("Failed to resume process");
    /// ```
    pub fn resume(&self) -> Result<(), Error> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(Error::last_os_error());
            }

            let mut entry: THREADENTRY32 = zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut entry) == 0 {
                CloseHandle(snapshot);
                return Err(Error::last_os_error());
            };

            loop {
                if entry.th32OwnerProcessID == self.pid {
                    let thread: HANDLE = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                    if !thread.is_null() {
                        ResumeThread(thread);
                        CloseHandle(thread);
                    }
                }

                if Thread32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }

            CloseHandle(snapshot);
            Ok(())
        }
    }

    /// # Explanation
    ///
    /// Checks if a threads exists and if it belongs to the current Process.
    /// If it doesn't it will return an [`Error`] else it will return `Ok(())` and therefore you can check with `result.is_ok()`
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// # use std::io::Error;
    /// let process = Process::new(1234);
    /// let thread_exists = process.thread_exists(1345);
    /// match thread_exists {
    ///       Ok(string) => println!("Read string: {}", string),
    ///       Err(e) => eprintln!("Failed to read string: {}", e),
    ///  }
    /// ```
    pub fn thread_exists(&self, thread_id: u32) -> Result<(), Error> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            let mut entry: THREADENTRY32 = zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;

            let mut found = false;
            if Thread32First(snapshot, &mut entry) != 0 {
                loop {
                    if entry.th32ThreadID == thread_id {
                        // Check if the thread belongs to the given in pid
                        if entry.th32OwnerProcessID != self.pid {
                            CloseHandle(snapshot);
                            return Err(Error::new(ErrorKind::NotFound, "Thread does not belong to target process "));
                        }
                        found = true;
                        break;
                    }

                    if Thread32Next(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            };

            CloseHandle(snapshot);

            // check if it was actually found once more and if not returning an error
            if !found {
                return Err(Error::new(ErrorKind::NotFound, "Thread not found"))
            }

            return Ok(());
        }
    }

    /// Suspends a specific thread by its thread ID.
    ///
    /// # Parameters
    /// - `thread_id`: The ID of the thread to suspend.
    ///
    /// # Returns
    /// - `Ok(())` if the thread was successfully suspended.
    /// - `Err(std::io::Error)` if an error occurred while attempting to suspend the thread.
    ///
    /// # Safety
    /// This function uses unsafe Windows API calls to manipulate thread state. Make sure
    /// the thread ID is valid and belongs to the expected process.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(1234);
    /// process.suspend_thread(12345).expect("Failed to suspend process");
    /// ```
    ///
    /// This method does not currently validate whether the thread belongs to the target process.
    /// You must ensure the thread ID is associated with `self.pid`.
    pub fn suspend_thread(&self, thread_id: u32) -> Result<(), Error> {
        unsafe {
            let thread_exists = self.thread_exists(thread_id);
            if thread_exists.is_err() {
                return Err(Error::last_os_error());
            }

            let thread: HANDLE = OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id);
            if thread.is_null() {
                return Err(Error::last_os_error());
            }

            let result = SuspendThread(thread);
            CloseHandle(thread);

            if result == u32::MAX {
                return Err(Error::last_os_error());
            }

            Ok(())
        }
    }

    /// Resumes a specific thread by its thread ID.
    ///
    /// # Parameters
    /// - `thread_id`: The ID of the thread to resume.
    ///
    /// # Returns
    /// - `Ok(())` if the thread was successfully resumed.
    /// - `Err(std::io::Error)` if an error occurred while attempting to resume the thread.
    ///
    /// # Safety
    /// This function uses unsafe Windows API calls to manipulate thread state. Make sure
    /// the thread ID is valid and belongs to the expected process.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(1234);
    /// let thread_id: u32 = 1234567;
    /// process.resume_thread(thread_id).expect("Failed to resume thread");
    /// ```
    pub fn resume_thread(&self, thread_id: u32) -> Result<(), Error> {
        unsafe {
            let thread_exists = self.thread_exists(thread_id);
            if thread_exists.is_err() {
                return Err(Error::last_os_error());
            }

            let thread: HANDLE = OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id);
            if thread.is_null() {
                return Err(Error::last_os_error());
            }

            let result = ResumeThread(thread);
            CloseHandle(thread);

            if result == u32::MAX {
                return Err(Error::last_os_error());
            }

            Ok(())
        }
    }

    /// Retrieves all threads IDs associated with the target process.
    ///
    /// # How?
    ///
    /// This function takes a snapshot of all threads in the system using [`CreateToolhelp32Snapshot`],
    /// and iterates trough each one using [`Thread32First`] and [`Thread32Next`]. If a thread belongs
    /// to the process specified by `self.pid`, it's ID is added to a `<Vec<u32>`.
    ///
    /// # Returns
    ///
    /// - `Ok(<Vec<u32>)` containing the threads IDs of the target process.
    /// - `Err(std::io::Error)` if creating the snapshot or enumerating the threads fails.
    ///
    /// # Safety
    ///
    /// This function performs unsafe Windows API calls including [`CreateToolhelp32Snapshot`],
    /// [`Thread32First`], and [`Thread32Next`] and must therefore be called with caution because
    /// improper use may lead to undefined behaviour or system instability.
    ///
    /// # Example
    /// ```rust
    /// # use memory_utils::process::Process;
    /// let process = Process::new(1234);
    /// let threads = process.get_threads().expect("Failed to get threads");
    /// for thread_id in threads {
    ///     println!("Threads ID: {}", thread_id)
    /// }
    /// ```
    pub fn get_threads(&self) -> Result<Vec<u32>, Error> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD , 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(Error::last_os_error());
            }

            let mut threads = Vec::new();
            let mut entry: THREADENTRY32 = zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut entry) == 0 {
                CloseHandle(snapshot);
                return Err(Error::last_os_error());
            };

            loop {
                if entry.th32OwnerProcessID == self.pid {
                    threads.push(entry.th32ThreadID);
                }

                if Thread32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }

            CloseHandle(snapshot);
            Ok(threads)
        }
    }
}

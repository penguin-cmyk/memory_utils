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


// Imports
use winapi::{
    um::{
        handleapi::{ CloseHandle, INVALID_HANDLE_VALUE },

        memoryapi::{
            WriteProcessMemory,
            ReadProcessMemory,
            VirtualQueryEx,
            VirtualProtectEx
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

        winnt::{
            MEMORY_BASIC_INFORMATION,
            PROCESS_VM_READ,
            PROCESS_QUERY_INFORMATION,
            PAGE_EXECUTE_READWRITE,
            MEM_COMMIT,
            PAGE_READWRITE,
            THREAD_SUSPEND_RESUME,
            PAGE_NOACCESS,
            PAGE_READONLY,
            PAGE_EXECUTE_READ,
            HANDLE,
            CONTEXT_ALL,
            THREAD_GET_CONTEXT,
            THREAD_QUERY_INFORMATION,
            CONTEXT,
            PROCESS_TERMINATE,
            LONG,
            LONGLONG,
            PROCESS_VM_WRITE,
            PROCESS_VM_OPERATION,
            PAGE_EXECUTE_WRITECOPY,
            PAGE_EXECUTE,
            PAGE_GUARD,
            PAGE_NOCACHE,
            PAGE_WRITECOMBINE,
            PAGE_WRITECOPY
        },
    },

    shared::{
        minwindef::{LPVOID, DWORD, LPCVOID} ,
    },

    ctypes::c_void as win_cvoid,
};

use std::{
    io::{ Error, ErrorKind },
    mem::{ zeroed, size_of },
    ffi::CStr,
    ptr,

};
use winapi::shared::minwindef::TRUE;

// Enum and Structs
pub struct Process {
    pid: u32
}

pub struct ModuleInfo {
    pub name: String,
    pub base_address: *mut win_cvoid,
    pub entry: MODULEENTRY32
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
    /// Creates a new Process handler with the given in Process ID.
    pub fn new(pid: u32) -> Self {
        Self { pid }
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
    /// * `Err(Error)` - if the process could not be opened or the query failed.
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
    /// * `Err(Error)` - If the snapshot or module iteration fails.
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
    /// * `Err(Error)` if the module is not found or an error occurs during the search.
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
    /// * `Err(Error)` - If the process isn't found or a system error occurred.
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
    ///- `Err(Error)` if the thread does not exist, cannot be opened, or [`GetThreadContext`] fails.
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
            let thread_exists = self.thread_exists(thread_id)?; // if thread doesn't exist this will error

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
    /// - `Err(Error)` if the process cannot be opened, memory cannot be read,
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
            let process = OpenProcess(PROCESS_VM_READ, 0, self.pid);
            if process.is_null() {
                return Err(Error::last_os_error());
            }

            let mut buffer = Vec::new();
            let mut offset = 0;

            loop {
                let mut byte: u8 = 0;
                let success = ReadProcessMemory(
                    process,
                    (address + offset) as LPCVOID,
                    &mut byte as *mut _ as LPVOID,
                    1,
                    ptr::null_mut(),
                );

                if success == 0 {
                    CloseHandle(process);
                    return Err(Error::last_os_error());
                }

                if byte == 0 { // null-terminator found
                    break;
                }

                buffer.push(byte);
                offset += 1;

                if offset > 4096 {
                    CloseHandle(process);
                    return Err(Error::new(ErrorKind::InvalidData, "String too long or not null-terminated"))
                }
            }
            CloseHandle(process);

            String::from_utf8(buffer).map_err(|e| Error::new(ErrorKind::InvalidData, e))

        }
    }

    /// Reads a portion of the stack memory of the specified thread.
    ///
    /// # How?
    /// This function uses [`OpenThread`] to obtain a handle to the specified thread, retrieves the thread context
    /// using [`GetThreadContext`], and calculates the stack address using the `Rsp` register. It then reads a total
    /// of `size_l + size_r` bytes from around the tack pointer using [`ReadProcessMemory`] and returns the resulting
    /// memory as a `Vec<u8>` or `Err(Error)` if the operation didn't succeed.
    ///
    /// # Parameters
    /// - `thread_id`: The thread ID (`u32`) of the target thread whose stack should be read.
    /// - `size_l`: The number of bytes to read before the current stack pointer (`RSP`). This is useful
    /// for examining the stack leading up to the current call frame.
    /// - `size_r`: The number of bytes to read after the current stack pointer.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)`: A vector of bytes containing the read stack memory
    /// - `Err(Error)`: If opening the thread, retrieving the thread context, or reading memory fails.
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
    /// println!("Read {} bytes from stack", stack_data.len());
    /// ```
    pub fn read_stack(&self, thread_id: u32, size_l: usize, size_r: usize) -> Result<Vec<u8>, Error> {
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

            let mut buffer = vec![0u8; total_size];
            let mut bytes_read = 0;

            let process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,0, self.pid);

            let success = ReadProcessMemory(
                process,
                start_addr as LPVOID,
                buffer.as_mut_ptr() as LPVOID,
                total_size,
                &mut bytes_read
            );
            CloseHandle(process);
            CloseHandle(thread);

            if success == 0 {
                return Err(Error::last_os_error())
            } else {
                buffer.truncate(bytes_read);
                Ok(buffer)
            }
        }
    }

    /// Converts a [`ProtectOptions`] variant into the corresponding `u32` memory protection constant
    /// used by the Windows API (e.g, [`PAGE_READONLY`], [`PAGE_READWRITE`], etc.)
    ///
    /// # Conversion Table
    ///
    /// | Variant       | Corresponding Constant  |
    /// |---------------|-------------------------|
    /// | `NoAccess`    | `PAGE_NOACCESS`         |
    /// | `ReadOnly`    | `PAGE_READONLY`         |
    /// | `ReadWrite`   | `PAGE_READWRITE`        |
    /// | `ExecuteRead` | `PAGE_EXECUTE_READ`     |
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
    pub fn protect_memory(&self, address: usize, size: usize, new_protect: ProtectOptions) -> Result<(), Error> {
        unsafe {
            let process = OpenProcess(PROCESS_VM_OPERATION, 0, self.pid);
            if process.is_null() {
                return Err(Error::last_os_error());
            }
            let mut old_protect: DWORD = 0;
            let result = VirtualProtectEx(
                process,
                address as LPVOID,
                size,
                new_protect.into(),
                &mut old_protect
            );
            CloseHandle(process);
            if result == 0 {
                return Err(Error::last_os_error());
            };
        }

        Ok(())
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

            let process: HANDLE = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, self.pid);
            if process.is_null() {
                return Err(Error::last_os_error());
            }

            let mut buffer: T = zeroed();
            let success = ReadProcessMemory(
                process,
                address as LPCVOID,
                &mut buffer as *mut _ as LPVOID,
                size_of::<T>(),
                ptr::null_mut()
            );

            CloseHandle(process);

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
            let process: HANDLE = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, self.pid);
            if process.is_null() {
                return Err(Error::last_os_error());
            }

            let success = WriteProcessMemory(
                process,
                address as LPVOID,
                value as *const _ as LPCVOID,
                size_of::<T>(),
                ptr::null_mut()
            );

            CloseHandle(process);

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
    fn find_pattern(&self, data: &[u8], pattern: &[u8], mask: &str ) -> Option<usize> {
        'search: for i in 0..=data.len().saturating_sub(pattern.len()) {
            for (j, &m) in mask.as_bytes().iter().enumerate() {
                if m == b'x' && data[i + j] != pattern[j] {
                    continue 'search;
                }
            }
            return Some(i);
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
            let process: HANDLE = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, self.pid);
            if process.is_null() {
                return Err(Error::last_os_error());
            }

            let mut addr: usize = 0;
            let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();

            while VirtualQueryEx(process, addr as LPCVOID, &mut mbi as *mut _, size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
                if mbi.State == MEM_COMMIT && (
                    mbi.Protect == PAGE_EXECUTE_READWRITE
                        || mbi.Protect ==  PAGE_READWRITE
                        || mbi.Protect == PAGE_READONLY ) &&
                    mbi.RegionSize > 0
                {
                    let mut buffer = vec![0u8; mbi.RegionSize];
                    let mut bytes_read = 0;

                    if ReadProcessMemory(
                        process,
                        addr as LPCVOID,
                        buffer.as_mut_ptr() as LPVOID,
                        mbi.RegionSize,
                        &mut bytes_read,
                    ) != 0 {
                        if let Some(found) = self.find_pattern(&buffer, pattern, mask) {
                            CloseHandle(process);
                            return Ok(addr + found);
                        }
                    }
                }

                addr += mbi.RegionSize;
            }

            CloseHandle(process);
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
    /// - `Err(Error)` if creating the snapshot or enumerating threads fails.
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
    /// - `Err(Error)` if creating the snapshot or enumerating threads fails.
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
    /// - `Err(Error)` if an error occurred while attempting to suspend the thread.
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
            if !thread_exists.is_ok() {
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
    /// - `Err(Error)` if an error occurred while attempting to resume the thread.
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
            if !thread_exists.is_ok() {
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
    /// - `Err(Error)` if creating the snapshot or enumerating the threads fails.
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
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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

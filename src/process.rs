#[cfg(target_os = "macos")]
use {
    mach2::{
        traps::{
            task_for_pid,
            mach_task_self
        },
        kern_return::KERN_SUCCESS,
        vm_statistics::VM_FLAGS_ANYWHERE,
        vm_types::{
            vm_offset_t,
            mach_vm_address_t,
            mach_vm_size_t
        },
        vm_region::{
            vm_region_basic_info_64,
            VM_REGION_BASIC_INFO_64,
            VM_REGION_BASIC_INFO_COUNT_64,
            vm_region_info_t,
            vm_region_basic_info_data_64_t,

        },
        task::{task_threads, task_resume, task_suspend},
        vm::*,
        thread_act::{
            thread_resume,
            thread_suspend,
        },
        port::MACH_PORT_NULL,
    },

    libc::*,
};

#[cfg(target_os = "windows")]
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
    ffi::CStr,
    io::{Error, ErrorKind}
};

pub struct Process {
    pub pid: u32,

    #[cfg(target_os = "macos")]
    pub task: mach_port_t,
    #[cfg(target_os = "windows")]
    pub handle: HANDLE,
}

pub struct ModuleInfo {
    pub name: String,
    pub base_address: usize,
    pub size: usize,

    #[cfg(target_os = "macos")]
    pub path: String,

    #[cfg(target_os = "windows")]
    pub entry: MODULEENTRY32,
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: usize,
    pub virtual_address: LPVOID,
    pub dumped_path: String
}

#[cfg(target_os = "windows")]
pub struct ExportInfo {
    pub export_info: IMAGE_EXPORT_DIRECTORY,
    pub export_directory_address: LPVOID,
}

#[cfg(target_os = "windows")]
pub struct PeInfo {
    pub sections: Vec<SectionInfo>,
    pub exports: Option<ExportInfo>,
}

#[derive(Debug, Clone)]
pub struct Pattern {
    pub pattern: String,
    pub name: String,
    pub library: String,
}

impl Pattern {
    pub fn new(pattern: impl Into<String>, name: impl Into<String>, library: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            name: name.into(),
            library: library.into(),
        }
    }
}

pub fn convert_pattern_to_bytes(pattern: &str) -> Option<(Vec<u8>, String)> {
    let mut bytes = Vec::new();
    let mut mask = String::new();


    let mut chars = pattern.chars().peekable();

    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }

        if c == '?' {
            bytes.push(0);
            mask.push('?');
            if chars.peek() == Some(&'?') {
                chars.next();
            }
            continue;
        }

        let upper = c.to_digit(16)?;
        let lower = chars.next()?.to_digit(16)?;

        bytes.push(((upper << 4) | lower) as u8);
        mask.push('x');
    }

    if bytes.is_empty() {
        return None;
    }

    Some((bytes, mask))
}

fn match_pattern(data: &[u8], pattern: &[u8], mask: &str) -> bool {
    if data.len() < pattern.len() {
        return false;
    }

    for (i, (&byte, mask_char)) in pattern.iter().zip(mask.chars()).enumerate() {
        if mask_char == 'x' && data[i] != byte {
            return false;
        }
    }

    true
}

#[cfg(target_os = "windows")]
fn search_memory_region_windows(
    handle: HANDLE,
    start_addr: usize,
    region_size: usize,
    pattern: &[u8],
    mask: &str,
) -> Option<usize> {
    if pattern.is_empty() || mask.is_empty() || pattern.len() != mask.len() {
        return None;
    }

    let mut buffer = vec![0u8; region_size];
    let mut bytes_read = 0usize;

    unsafe {
        if ReadProcessMemory(
            handle,
            start_addr as *const _,
            buffer.as_mut_ptr() as *mut _,
            region_size,
            Some(&mut bytes_read),
        )
            .is_err()
        {
            return None;
        }
    }

    if bytes_read < pattern.len() {
        return None;
    }

    for offset in 0..=(bytes_read - pattern.len()) {
        if match_pattern(&buffer[offset..], pattern, mask) {
            return Some(start_addr + offset);
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn search_memory_region_macos(
    task: mach_port_t,
    start_addr: mach_vm_address_t,
    region_size: mach_vm_size_t,
    pattern: &[u8],
    mask: &str,
) -> Option<usize> {
    if pattern.is_empty() || mask.is_empty() || pattern.len() != mask.len() {
        return None;
    }

    let mut buffer = vec![0u8; region_size as usize];
    let mut bytes_read: mach_vm_size_t = 0;

    unsafe {
        if mach_vm_read_overwrite(
            task,
            start_addr,
            region_size,
            buffer.as_mut_ptr() as mach_vm_address_t,
            &mut bytes_read,
        ) != KERN_SUCCESS
        {
            return None;
        }
    }

    if (bytes_read as usize) < pattern.len() {
        return None;
    }

    for offset in 0..=(bytes_read as usize - pattern.len()) {
        if match_pattern(&buffer[offset..], pattern, mask) {
            return Some(start_addr as usize + offset);
        }
    }

    None
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
        #[cfg(target_os = "windows")]
        {
            match opt {
                ProtectOptions::NoAccess => PAGE_NOACCESS.0,
                ProtectOptions::ReadOnly => PAGE_READONLY.0,
                ProtectOptions::ReadWrite => PAGE_READWRITE.0,
                ProtectOptions::WriteCopy => PAGE_WRITECOPY.0,
                ProtectOptions::Execute => PAGE_EXECUTE.0,
                ProtectOptions::ExecuteRead => PAGE_EXECUTE_READ.0,
                ProtectOptions::ExecuteReadWrite => PAGE_EXECUTE_READWRITE.0,
                ProtectOptions::ExecuteWriteCopy => PAGE_EXECUTE_WRITECOPY.0,
                ProtectOptions::Guard => PAGE_GUARD.0,
                ProtectOptions::NoCache => PAGE_NOCACHE.0,
                ProtectOptions::WriteCombine => PAGE_WRITECOMBINE.0,
            }
        }

        #[cfg(target_os = "macos")]
        {
            match opt {
                ProtectOptions::NoAccess => VM_PROT_NONE as u32,
                ProtectOptions::ReadOnly => VM_PROT_READ as u32,
                ProtectOptions::ReadWrite => (VM_PROT_READ | VM_PROT_WRITE) as u32,
                ProtectOptions::Execute => VM_PROT_EXECUTE as u32,
                ProtectOptions::ExecuteRead => (VM_PROT_READ | VM_PROT_EXECUTE) as u32,
                ProtectOptions::ExecuteReadWrite => {
                    (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE) as u32
                }
                ProtectOptions::WriteCopy
                | ProtectOptions::ExecuteWriteCopy
                | ProtectOptions::Guard
                | ProtectOptions::NoCache
                | ProtectOptions::WriteCombine => VM_PROT_NONE as u32,
            }
        }
    }
}

impl From<u32> for ProtectOptions {
    fn from(opt: u32) -> Self {
        #[cfg(target_os = "windows")]
        {
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
                _ => ProtectOptions::NoAccess,
            }
        }

        #[cfg(target_os = "macos")]
        {
            let r = (opt & VM_PROT_READ as u32) != 0;
            let w = (opt & VM_PROT_WRITE as u32) != 0;
            let x = (opt & VM_PROT_EXECUTE as u32) != 0;

            match (r, w, x) {
                (false, false, false) => ProtectOptions::NoAccess,
                (true, false, false) => ProtectOptions::ReadOnly,
                (true, true, false) => ProtectOptions::ReadWrite,
                (false, false, true) => ProtectOptions::Execute,
                (true, false, true) => ProtectOptions::ExecuteRead,
                (true, true, true) => ProtectOptions::ExecuteReadWrite,
                _ => ProtectOptions::NoAccess,
            }
        }
    }
}

unsafe impl Send for Process {}
unsafe impl Sync for Process {}

#[cfg(target_os = "macos")]
pub fn mac_err(function: &str, result: kern_return_t) -> Error {
    Error::new(
        ErrorKind::Other,
        format!("{} failed with code {}", function, result)
    )
}

impl Process {

    pub fn clone(&self) -> Process {
        #[cfg(target_os = "windows")]
        return Process { pid: self.pid, handle: self.handle };

        #[cfg(target_os = "macos")]
        return Process { pid: self.pid, task: self.task };
    }

    pub fn new(pid: u32) -> Result<Process, Error> {
        #[cfg(target_os = "windows")]
        {
            let handle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_TERMINATE, 0, pid) };

            if handle.is_null() {
                return Err(Error::last_os_error());
            }

            Ok(Self { pid, handle })
        }
        #[cfg(target_os = "macos")]
        {
            let mut task: mach_port_t = 0;
            let result = unsafe {
                task_for_pid(mach_task_self(), pid as i32, &mut task)
            };
            if result != KERN_SUCCESS {
                return Err(mac_err("task_for_pid", result));
            }

            Ok(Self{ pid, task})
        }

    }

    pub fn write_bytes(&self, address: usize, bytes: &[u8]) -> Result<(), Error> {
        #[cfg(target_os = "windows")]
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
        #[cfg(target_os = "macos")]
        unsafe {
            let result = mach_vm_write(self.task, address as u64, bytes.as_ptr() as vm_offset_t, bytes.len() as u32);

            if result != KERN_SUCCESS {
                return Err(mac_err("mach_vm_write", result));
            }

            Ok(())
        }
    }

    pub fn read_bytes(&self, address: usize, length: usize) -> Result<Vec<u8>, Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            let mut bytes_read = 0;
            let mut buffer = vec![0u8; length];
            let success = ReadProcessMemory(self.handle, address as LPCVOID, buffer.as_mut_ptr() as LPVOID, length, &mut bytes_read);

            if success == 0 {
                return Err(Error::last_os_error());
            }

            buffer.set_len(bytes_read);
            Ok(buffer)
        }

        #[cfg(target_os = "macos")]
        unsafe {

            let mut data: vm_offset_t = 0;
            let mut data_size: mach_msg_type_number_t = 0;

            let result = mach_vm_read(self.task, address as mach_vm_address_t, length as mach_vm_size_t, &mut data, &mut data_size);

            if result != KERN_SUCCESS {
                return Err(mac_err("mach_vm_read", result));
            }

            let buffer = std::slice::from_raw_parts(data as *const u8, data_size as usize).to_vec();

            mach_vm_deallocate(mach_task_self(), data as mach_vm_address_t, data as u64);

            Ok(buffer)
        }
    }

    pub fn read_string(&self, address: usize, max_length: usize) -> Result<String, Error> {
        let bytes = self.read_bytes(address, max_length)?;
        let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let string = String::from_utf8(bytes[..null_pos].to_vec()).map_err(|_| Error::last_os_error())?;
        Ok(string)
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

    pub fn place_absolute_jmp(&self, address: usize, destination: usize) -> Result<bool, Error>
    {
        // mov rax, imm64
        let mut patch: Vec<u8> = vec![0x48; 0xB8];
        patch.extend_from_slice(&(destination as u64).to_le_bytes());
        // jmp rax
        patch.extend_from_slice(&[0xFF, 0xE0]);

        #[cfg(target_os = "windows")]
        unsafe {
            let mut old_protect = 0;
            let result = VirtualProtectEx(
                self.handle,
                address as LPVOID,
                patch.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect
            );

            if result == 0 {
                return Err(Error::last_os_error());
            }

            let mut written = 0;
            let success = WriteProcessMemory(
                self.handle,
                address as LPVOID,
                patch.as_ptr() as LPCVOID,
                patch.len(),
                &mut written,
            );

            VirtualProtectEx(self.handle, address as LPVOID, patch.len(), old_protect, &mut 0);

            if success == 0 || written != patch.len() {
                return Err(Error::last_os_error());
            }

            Ok(true)
        }

        #[cfg(target_os = "macos")]
        unsafe {
            let result = mach_vm_protect(
                self.task,
                address as mach_vm_address_t,
                patch.len() as mach_vm_size_t,
                0,
                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
            );

            if result != KERN_SUCCESS {
                return Err(mac_err("mach_vm_protect", result));
            }

            let result = mach_vm_write(
                self.task,
                address as mach_vm_address_t,
                patch.as_ptr() as vm_offset_t,
                patch.len() as u32,
            );

            if result != KERN_SUCCESS {
                return Err(mac_err("mach_vm_write", result));
            }

            Ok(true)
        }
    }

    pub fn allocate(&self, size: usize) -> Result<*mut u8, Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            let allocated = VirtualAllocEx(self.handle, std::ptr::null_mut(), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if allocated.is_null() {
                return Err(Error::last_os_error());
            }

            Ok(allocated as *mut u8)
        }

        #[cfg(target_os = "macos")]
        unsafe {
            let mut allocated: mach_vm_address_t = 0;
            let result = mach_vm_allocate(self.task, &mut allocated, size as mach_vm_size_t, VM_FLAGS_ANYWHERE); // VM_FLAGS_ANYWHERE = let kernel choose address

            if result != KERN_SUCCESS {
                return Err(mac_err("mach_vm_allocate", result));
            }

            let protect_result = mach_vm_protect(self.task, allocated as mach_vm_address_t, size as mach_vm_size_t, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE, );

            if protect_result != KERN_SUCCESS {
                return Err(mac_err("mach_vm_protect", protect_result));
            }

            Ok(allocated as *mut u8)
        }
    }

    pub fn trampoline_hook(&self, target_address: usize, hook_address: usize, hook_length: usize) -> Result<*const u8, Error> {
        #[cfg(target_os = "windows")]
        unsafe {

            // Allocate enough for original bytes + 12 bytes for jump back (mov rax + jmp rax)
            // trampoline = [original bytes] + [mov rax, return_addr] + [jmp rax]
            let trampoline_size = hook_length + 12;
            let trampoline = VirtualAllocEx(
                self.handle,
                ptr::null_mut(),
                trampoline_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            );

            if trampoline.is_null() {
                return Err(Error::last_os_error());
            }

            let mut original_bytes = vec![0u8; hook_length];
            let mut bytes_read = 0;
            let success = ReadProcessMemory(
                self.handle,
                target_address as LPCVOID,
                original_bytes.as_mut_ptr() as LPVOID,
                hook_length,
                &mut bytes_read
            );

            if success == 0 || bytes_read != hook_length {
                VirtualFreeEx(self.handle, trampoline, 0, MEM_RELEASE);
                return Err(Error::last_os_error());
            }

            let mut written = 0;
            let success = WriteProcessMemory(
                self.handle,
                trampoline,
                original_bytes.as_ptr() as LPCVOID,
                hook_length,
                &mut written
            );

            if success == 0 || written != hook_length {
                VirtualFreeEx(self.handle, trampoline, 0, MEM_RELEASE);
                return Err(Error::new(ErrorKind::Other, "Failed to write original bytes to trampoline"));
            }

            let jump_back_addr = target_address + hook_length;
            let mut jump_back_patch: Vec<u8> = vec![0x48, 0xB8]; // mov rax, imm64
            jump_back_patch.extend_from_slice(&(jump_back_addr as u64).to_le_bytes());
            jump_back_patch.extend_from_slice(&[0xFF, 0xE0]); // jmp rax

            let success = WriteProcessMemory(
                self.handle,
                (trampoline as usize + hook_length) as LPVOID,
                jump_back_patch.as_ptr() as LPCVOID,
                jump_back_patch.len(),
                &mut written
            );

            if success == 0 || written != jump_back_patch.len() {
                VirtualFreeEx(self.handle, trampoline, 0, MEM_RELEASE);
                return Err(Error::new(ErrorKind::Other, "Failed to write jump back"));
            }

            let mut old_protect = 0;
            let mut patch: Vec<u8> = vec![0x48, 0xB8]; // mov rax, imm64
            patch.extend_from_slice(&(hook_address as u64).to_le_bytes());
            patch.extend_from_slice(&[0xFF, 0xE0]); // jmp rax

            let success = VirtualProtectEx(
                self.handle,
                target_address as LPVOID,
                patch.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect
            );

            if success == 0 {
                VirtualFreeEx(self.handle, trampoline, 0, MEM_RELEASE);
                return Err(Error::last_os_error());
            }

            let success = WriteProcessMemory(
                self.handle,
                target_address as LPVOID,
                patch.as_ptr() as LPCVOID,
                patch.len(),
                &mut written
            );

            let mut temp = 0;
            VirtualProtectEx(self.handle, target_address as LPVOID, patch.len(), old_protect, &mut temp);

            if success == 0 || written != patch.len() {
                VirtualFreeEx(self.handle, trampoline, 0, MEM_RELEASE);
                return Err(Error::new(ErrorKind::Other, "Failed to write hook"));
            }

            Ok(trampoline as *const u8)
        }

        #[cfg(target_os = "macos")]
        unsafe {
            let trampoline_size = hook_length + 12;
            let mut trampoline: mach_vm_address_t = 0;

            let result = mach_vm_allocate(
                self.task,
                &mut trampoline,
                trampoline_size as mach_vm_size_t,
                VM_FLAGS_ANYWHERE
            );

            if result != KERN_SUCCESS {
                return Err(mac_err("mach_vm_allocate", result));
            }

            let result = mach_vm_protect(
                self.task,
                trampoline,
                trampoline_size as mach_vm_size_t,
                0,
                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
            );

            if result != KERN_SUCCESS {
                mach_vm_deallocate(self.task, trampoline, trampoline_size as mach_vm_size_t);
                return Err(mac_err("mach_vm_deallocate", result));
            }

            let mut data: vm_offset_t = 0;
            let mut data_size: mach_msg_type_number_t = 0;

            let result = mach_vm_read(
                self.task,
                target_address as mach_vm_address_t,
                hook_length as mach_vm_size_t,
                &mut data,
                &mut data_size
            );

            if result != KERN_SUCCESS {
                mach_vm_deallocate(self.task, trampoline, trampoline_size as mach_vm_size_t);
                return Err(mac_err("mach_vm_read", result));
            }

            let original_bytes = std::slice::from_raw_parts(data as *const u8, data_size as usize).to_vec();
            mach_vm_deallocate(mach_task_self(), data as mach_vm_address_t, data_size as u64);

            let result = mach_vm_write(
                self.task,
                trampoline,
                original_bytes.as_ptr() as vm_offset_t,
                original_bytes.len() as u32
            );

            if result != KERN_SUCCESS {
                mach_vm_deallocate(self.task, trampoline, trampoline_size as mach_vm_size_t);
                return Err(mac_err("mach_vm_deallocate", result));
            }

            let jump_back_addr = target_address + hook_length;
            let mut jump_back_patch: Vec<u8> = vec![0x48, 0xB8]; // mov rax, imm64
            jump_back_patch.extend_from_slice(&(jump_back_addr as u64).to_le_bytes());
            jump_back_patch.extend_from_slice(&[0xFF, 0xE0]); // jmp rax

            let result = mach_vm_write(
                self.task,
                trampoline + hook_length as u64,
                jump_back_patch.as_ptr() as vm_offset_t,
                jump_back_patch.len() as u32
            );

            if result != KERN_SUCCESS {
                mach_vm_deallocate(self.task, trampoline, trampoline_size as mach_vm_size_t);
                return Err(mac_err("mach_vm_write", result));
            }

            let mut patch: Vec<u8> = vec![0x48, 0xB8]; // mov rax, imm64
            patch.extend_from_slice(&(hook_address as u64).to_le_bytes());
            patch.extend_from_slice(&[0xFF, 0xE0]); // jmp rax

            let result = mach_vm_protect(
                self.task,
                target_address as mach_vm_address_t,
                patch.len() as mach_vm_size_t,
                0,
                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_READ
            );

            if result != KERN_SUCCESS {
                mach_vm_deallocate(self.task, trampoline, trampoline_size as mach_vm_size_t);
                return Err(mac_err("mach_vm_protect", result));
            }

            let result = mach_vm_write(
                self.task,
                target_address as u64,
                patch.as_ptr() as vm_offset_t,
                patch.len() as u32
            );

            if result != KERN_SUCCESS {
                mach_vm_deallocate(self.task, trampoline, trampoline_size as mach_vm_size_t);
                return Err(mac_err("mach_vm_write", result));
            }

            Ok(trampoline as *const u8)
        }
    }

    pub fn get_modules(&self) -> Result<Vec<ModuleInfo>, Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(Error::last_os_error());
            }

            let mut entry: MODULEENTRY32 = std::mem::zeroed();
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
                    name,
                    base_address: entry.modBaseAddr as usize,
                    size: entry.modBaseSize as usize,
                    entry,
                });

                if Module32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }

            CloseHandle(snapshot);
            Ok(result)
        }

        #[cfg(target_os = "macos")]
        unsafe {
            let mut modules: Vec<ModuleInfo> = Vec::new();
            let mut address: mach_vm_address_t = 0;
            let mut seen_paths = std::collections::HashSet::new();

            loop {
                let mut info: vm_region_basic_info_64 = std::mem::zeroed();
                let mut info_count = (size_of::<vm_region_basic_info_64>() / size_of::<i32>()) as u32;
                let mut object_name: u32 = 0;
                let mut size: mach_vm_size_t = 0;

                let kr = mach_vm_region(
                    self.task,
                    &mut address,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    &mut info as *mut _ as *mut i32,
                    &mut info_count,
                    &mut object_name,
                );

                if kr != KERN_SUCCESS {
                    break;
                }

                let mut path_buf = vec![0i8; MAXPATHLEN as usize];
                let ret = proc_regionfilename(
                    self.pid as i32,
                    address as u64,
                    path_buf.as_mut_ptr() as *mut _,
                    MAXPATHLEN as u32
                );

                if ret > 0 {
                    let path_cstr = CStr::from_ptr(path_buf.as_ptr());
                    let path = path_cstr.to_string_lossy().into_owned();

                    if !path.is_empty() && !seen_paths.contains(&path) {
                        seen_paths.insert(path.clone());

                        let name = path.split('/').last().unwrap_or(&path).to_string();
                        modules.push(ModuleInfo {
                            name,
                            base_address: address as usize,
                            size: size as usize,
                            path
                        })
                    }
                }

                address += size;
            }

            Ok(modules)
        }
    }

    pub fn get_module(&self, module_name: &str) -> Result<ModuleInfo, Error> {
        let modules = self.get_modules()?;

        for m in modules {
            if m.name == module_name {
                return Ok(m);
            }
        }

        Err(Error::new(ErrorKind::NotFound, "Module not found"))
    }

    pub fn terminate(&self) -> Result<(), Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            let success = TerminateProcess(self.pid, 0);
            if success == 0 {
                return Err(Error::last_os_error());
            }

            Ok(())
        }

        #[cfg(target_os = "macos")]
        unsafe {
            let result = kill(self.pid as i32, SIGKILL);
            if result != KERN_SUCCESS {
                return Err(Error::last_os_error());
            }
            Ok(())
        }
    }

    #[cfg(target_os = "windows")]
    pub fn pe_headers(&self, base_address: *mut u8, sanitize_sections: bool) -> Result<PeInfo, Error>  {
        unsafe {
            let mut dos_headers: IMAGE_DOS_HEADER = zeroed();
            let base_address = base_address as usize;

            let success = ReadProcessMemory(
                self.handle,
                base_address as LPCVOID,
                &mut dos_headers as *mut _ as LPVOID,
                size_of::<IMAGE_DOS_HEADER>(),
                ptr::null_mut()
            );

            if success == 0 {
                return Err(Error::last_os_error());
            }

            // If a file doesn't begin with "MZ" (0x5A4D), it is not a valid PE file, and trying to parse further (e.g. jumping to e_lfanew)
            // would be dangerous and could cause a crash or garbage results.
            if dos_headers.e_magic != 0x5A4D {
                return Err(Error::new(ErrorKind::InvalidData, format!("Invalid DOS header: {}", dos_headers.e_magic)));
            }

            // e_lfanew points to the NT header.
            let nt_header_addr = base_address + dos_headers.e_lfanew as usize;
            let mut nt_headers: IMAGE_NT_HEADERS64 = zeroed();

            let success = ReadProcessMemory(
                self.handle,
                nt_header_addr as LPCVOID,
                &mut nt_headers as *mut _ as LPVOID,
                size_of::<IMAGE_NT_HEADERS64>(),
                ptr::null_mut()
            );

            if success == 0 {
                return Err(Error::last_os_error());
            }

            // 0x00004550 (PE\0\0) is the signature of the IMAGE_NT_HEADERS, which marks the start of the main PE header in a Windows binary.
            if nt_headers.Signature != 0x00004550 {
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
                    self.handle,
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
                let section_size = *section.Misc.VirtualSize() as usize;

                if section_size == 0 {
                    continue
                }

                let mut buffer = Vec::with_capacity(section_size);
                buffer.set_len(section_size);

                let success = ReadProcessMemory(
                    self.handle,
                    section_base as LPCVOID,
                    buffer.as_mut_ptr() as LPVOID,
                    section_size,
                    std::ptr::null_mut()
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

                std::fs::write(&path, &cleaned_data)?;

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
                    self.handle,
                    export_dir_addr as LPCVOID,
                    &mut export_dir as *mut _ as LPVOID,
                    size_of::<IMAGE_EXPORT_DIRECTORY>(),
                    std::ptr::null_mut()
                );

                if success == 0 { return  Err(Error::last_os_error()) }


                Some( ExportInfo {
                    export_info: export_dir,
                    export_directory_address: export_dir_addr as LPVOID
                } )
            } else {
                None
            };
            
            Ok(PeInfo {
                sections,
                exports: export_info
            })
        }
    }

    pub fn get_protection(&self, address: usize) -> Result<ProtectOptions, Error> {
        unsafe {
            #[cfg(target_os = "windows")]
            {

                let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
                let success = VirtualQueryEx(
                    self.handle,
                    address as LPCVOID,
                    &mut mbi,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if success == 0 {
                    return Err(Error::last_os_error());
                }

                CloseHandle(process);
                Ok(ProtectOptions::from(mbi.Protect))
            }

            #[cfg(target_os = "macos")]
            {
                use mach2::vm::*;

                let mut region_address = address as mach_vm_address_t;
                let mut region_size: mach_vm_size_t = 0;

                let mut info = vm_region_basic_info_64::default();
                let mut info_count = VM_REGION_BASIC_INFO_COUNT_64;
                let mut object_name: mach_port_t = 0;

                let kr = mach_vm_region(
                    self.task,
                    &mut region_address,
                    &mut region_size,
                    VM_REGION_BASIC_INFO_64,
                    (&mut info as *mut _) as vm_region_info_t,
                    &mut info_count,
                    &mut object_name,
                );

                if kr != KERN_SUCCESS {
                    return Err(mac_err("mach_vm_region", kr));
                }

                Ok(ProtectOptions::from(info.protection as u32))
            }
        }
    }

    pub fn is_valid_address(&self, address: usize) -> Result<bool, Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            let mut mbi = zeroed::<MEMORY_BASIC_INFORMATION>();
            let success = VirtualQueryEx(self.handle, address as LPCVOID, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>());
            Ok(success != 0)
        }

        #[cfg(target_os = "macos")]
        unsafe {
            let mut region_address = address as mach_vm_address_t;
            let mut region_size: mach_vm_size_t = 0;
            let mut info = vm_region_basic_info_64::default();
            let mut info_count = VM_REGION_BASIC_INFO_COUNT_64;
            let mut object_name: mach_port_t = 0;

            let kr = mach_vm_region(
                self.task,
                &mut region_address,
                &mut region_size,
                VM_REGION_BASIC_INFO_64,
                (&mut info as *mut _) as vm_region_info_t,
                &mut info_count,
                &mut object_name,
            );

            Ok(kr == KERN_SUCCESS)
        }
    }

    pub fn protect_memory(&self, address: usize, size: usize, new_protect: ProtectOptions) -> Result<ProtectOptions, Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            let mut old_protect: DWORD = 0;
            let result = VirtualProtectEx(
                self.handle,
                address as LPVOID,
                size,
                new_protect.into(),
                &mut old_protect,
            );
            if result == 0 {
                return Err(Error::last_os_error());
            }
            Ok(ProtectOptions::from(old_protect))
        }

        #[cfg(target_os = "macos")]
        unsafe {
            let mask: u32 = new_protect.into();

            let mut prot: i32 = 0;

            if mask & (ProtectOptions::ReadOnly as u32 | ProtectOptions::ReadWrite as u32) != 0 {
                prot |= VM_PROT_READ;
            }
            if mask & (ProtectOptions::ReadWrite as u32) != 0 {
                prot |= VM_PROT_WRITE;
            }
            if mask & (ProtectOptions::Execute as u32) != 0 {
                prot |= VM_PROT_EXECUTE;
            }

            let kr = mach_vm_protect(
                self.task,
                address as mach_vm_address_t,
                size as mach_vm_size_t,
                0,  // set_max = 0 (don’t change max protection)
                prot,
            );

            if kr != KERN_SUCCESS {
                return Err(Error::new(ErrorKind::Other, format!("vm_protect failed: {}", kr)));
            }

            Ok(ProtectOptions::from(mask))
        }
    }

    pub fn read_memory<T: Copy + Sized>(&self, address: usize) -> Result<T, Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            let mut buffer: T = std::mem::zeroed();
            let success = ReadProcessMemory(
                self.handle,
                address as LPCVOID,
                &mut buffer as *mut _ as LPVOID,
                size_of::<T>(),
                std::ptr::null_mut()
            );

            if success == 0 {
                return Err(Error::last_os_error());
            } else {
                Ok(buffer)
            }
        }

        #[cfg(target_os = "macos")]
        unsafe {
            let mut buffer: T = std::mem::zeroed();
            let mut out_size: mach_vm_size_t = 0;

            let kr = mach_vm_read_overwrite(
                self.task,
                address as mach_vm_address_t,
                size_of::<T>() as mach_vm_size_t,
                &mut buffer as *mut _ as mach_vm_address_t,
                &mut out_size,
            );

            if kr != KERN_SUCCESS || out_size != size_of::<T>() as u64 {
                Err(Error::new(ErrorKind::Other, format!("mach_vm_read_overwrite failed: {}", kr)))
            } else {
                Ok(buffer)
            }
        }
    }

    pub fn write_memory<T: Copy + Sized>(&self, address: usize, value: &T) -> Result<(), Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            let success = WriteProcessMemory(
                self.handle,
                address as LPVOID,
                value as *const _ as LPCVOID,
                size_of::<T>(),
                ptr::null_mut(),
            );
            if success == 0 { Err(Error::last_os_error()) } else { Ok(()) }
        }

        #[cfg(target_os = "macos")]
        unsafe {
            let data_ptr = value as *const T as vm_offset_t;
            let kr = mach_vm_write(
                self.task,
                address as mach_vm_address_t,
                data_ptr,
                size_of::<T>() as mach_msg_type_number_t,
            );

            if kr != KERN_SUCCESS {
                Err(Error::new(ErrorKind::Other, format!("mach_vm_write failed: {}", kr)))
            } else {
                Ok(())
            }
        }
    }


    pub fn pid(name: &str) -> Result<u32, Error> {
        #[cfg(target_os = "windows")]
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

        #[cfg(target_os = "macos")]
        unsafe {
            let max_pids = 1024;
            let mut pids = vec![0u32; max_pids];
            let count = proc_listpids(1 /* PROC_ALL_PIDS */, 0, pids.as_mut_ptr() as *mut _, (max_pids * size_of::<u32>()) as i32);
            if count <= 0 {
                return Err(Error::new(ErrorKind::Other, "proc_listpids failed"));
            }
            let pid_count = count as usize / size_of::<u32>();

            for &pid in &pids[..pid_count] {
                if pid == 0 { continue; }
                let mut path_buf = [0i8; MAXPATHLEN as usize];
                if proc_pidpath(pid as i32, path_buf.as_mut_ptr() as *mut _, MAXPATHLEN as u32) > 0 {
                    let path = CStr::from_ptr(path_buf.as_ptr()).to_string_lossy();
                    if path.contains(name) {
                        return Ok(pid);
                    }
                }
            }
            Err(Error::new(ErrorKind::NotFound, "Process not found"))
        }
    }

    pub fn get_base_address(&self) -> Result<usize, Error> {
        #[cfg(target_os = "windows")]
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

            CloseHandle(snapshot);
            Ok(entry.hModule as usize)
        }

        #[cfg(target_os = "macos")]
        unsafe {
            let mut size: mach_vm_size_t = 0;
            let mut address: mach_vm_address_t = 0;

            let mut info: vm_region_basic_info_64 = std::mem::zeroed();
            let mut info_count = VM_REGION_BASIC_INFO_COUNT_64;
            let mut object_name: mach_port_t = MACH_PORT_NULL;

            loop {
                let kr = mach_vm_region(
                    self.task,
                    &mut address,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    (&mut info as *mut _) as vm_region_info_t,
                    &mut info_count,
                    &mut object_name,
                );

                if kr != KERN_SUCCESS {
                    break;
                }

                if info.protection & VM_PROT_EXECUTE != 0 {
                    return Ok(address as usize);
                }

                address += size;
            }

            Err(Error::new(
                ErrorKind::NotFound,
                "Could not find executable base address",
            ))

        }
    }

    pub fn get_base_size(&self) -> Result<usize, Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(Error::last_os_error());
            }

            let mut entry: MODULEENTRY32 = std::mem::zeroed();
            entry.dwSize = size_of::<MODULEENTRY32>() as u32;

            if Module32First(snapshot, &mut entry) == 0 {
                CloseHandle(snapshot);
                return Err(Error::last_os_error());
            }

            CloseHandle(snapshot);
            Ok(entry.modBaseSize as usize)
        }

        #[cfg(target_os = "macos")]
        unsafe {
            let base_addr = self.get_base_address()? as mach_vm_address_t;
            let mut address = base_addr;
            let mut total_size: mach_vm_size_t = 0;

            loop {
                let mut size: mach_vm_size_t = 0;
                let mut info: vm_region_basic_info_64 = std::mem::zeroed();
                let mut info_count = VM_REGION_BASIC_INFO_COUNT_64;
                let mut object_name: mach_port_t = MACH_PORT_NULL;

                let kr = mach_vm_region(
                    self.task,
                    &mut address,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    (&mut info as *mut _) as vm_region_info_t,
                    &mut info_count,
                    &mut object_name,
                );

                if kr != KERN_SUCCESS {
                    break;
                }

                if address != base_addr + total_size {
                    break;
                }

                total_size += size;
                address += size;
            }

            Ok(total_size as usize)
        }
    }

    pub fn get_threads(&self) -> Result<Vec<u32>, Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(Error::last_os_error());
            }

            let mut threads = Vec::new();
            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut entry) == 0 {
                CloseHandle(snapshot);
                return Err(Error::last_os_error());
            }

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

        #[cfg(target_os = "macos")]
        unsafe {
            let mut thread_list: *mut u32 = std::ptr::null_mut();
            let mut thread_count: u32 = 0;

            if task_threads(self.task, &mut thread_list, &mut thread_count) != KERN_SUCCESS {
                return Err(Error::new(
                    ErrorKind::Other,
                    "task_threads failed",
                ));
            }

            let threads = std::slice::from_raw_parts(thread_list, thread_count as usize)
                .iter()
                .copied()
                .collect();

            vm_deallocate(
                mach_task_self(),
                thread_list as vm_address_t,
                (thread_count as usize) * size_of::<u32>(),
            );

            Ok(threads)
        }
    }

    fn thread_exists(&self, thread_id: u32) -> Result<bool, Error> {
        let threads = self.get_threads()?;
        Ok(threads.contains(&thread_id))
    }

    pub fn suspend_thread(&self, thread_id: u32) -> Result<(), Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            if !self.thread_exists(thread_id)? {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "Thread not found",
                ));
            }

            let thread = OpenThread(THREAD_SUSPEND_RESUME, false, thread_id);
            if thread.is_invalid() {
                return Err(Error::last_os_error());
            }

            let result = SuspendThread(thread);
            CloseHandle(thread);

            if result == u32::MAX {
                return Err(Error::last_os_error());
            }

            Ok(())
        }

        #[cfg(target_os = "macos")]
        unsafe {
            if !self.thread_exists(thread_id)? {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "Thread not found",
                ));
            }

            if thread_suspend(thread_id) != KERN_SUCCESS {
                return Err(Error::new(
                    ErrorKind::Other,
                    "thread_suspend failed",
                ));
            }

            Ok(())
        }
    }

    pub fn resume_thread(&self, thread_id: u32) -> Result<(), Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            if !self.thread_exists(thread_id)? {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "Thread not found",
                ));
            }

            let thread = OpenThread(THREAD_SUSPEND_RESUME, false, thread_id);
            if thread.is_invalid() {
                return Err(Error::last_os_error());
            }

            let result = ResumeThread(thread);
            CloseHandle(thread);

            if result == u32::MAX {
                return Err(Error::last_os_error());
            }

            Ok(())
        }

        #[cfg(target_os = "macos")]
        unsafe {
            if !self.thread_exists(thread_id)? {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "Thread not found",
                ));
            }

            if thread_resume(thread_id) != KERN_SUCCESS {
                return Err(Error::new(
                    ErrorKind::Other,
                    "thread_resume failed",
                ));
            }

            Ok(())
        }
    }

    pub fn suspend(&self) -> Result<(), Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(Error::last_os_error());
            }

            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut entry) == 0 {
                CloseHandle(snapshot);
                return Err(Error::last_os_error());
            }

            loop {
                if entry.th32OwnerProcessID == self.pid {
                    let thread = OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID);
                    if !thread.is_invalid() {
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

        #[cfg(target_os = "macos")]
        unsafe {
            if task_suspend(self.task) != KERN_SUCCESS {
                return Err(Error::new(
                    ErrorKind::Other,
                    "task_suspend failed",
                ));
            }
            Ok(())
        }
    }

    pub fn resume(&self) -> Result<(), Error> {
        #[cfg(target_os = "windows")]
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(Error::last_os_error());
            }

            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut entry) == 0 {
                CloseHandle(snapshot);
                return Err(Error::last_os_error());
            }

            loop {
                if entry.th32OwnerProcessID == self.pid {
                    let thread = OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID);
                    if !thread.is_invalid() {
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

        #[cfg(target_os = "macos")]
        unsafe {
            if task_resume(self.task) != KERN_SUCCESS {
                return Err(Error::new(
                    ErrorKind::Other,
                    "task_resume failed",
                ));
            }
            Ok(())
        }
    }

    pub fn pattern_scan(
        &self,
        pattern_str: &str,
        start_addr: Option<usize>,
        end_addr: Option<usize>,
    ) -> Result<Option<usize>, Error> {
        let (pattern, mask) = convert_pattern_to_bytes(pattern_str).ok_or_else(|| {
            Error::new(ErrorKind::InvalidInput, "Invalid pattern format")
        })?;

        self.pattern_scan_bytes(&pattern, &mask, start_addr, end_addr)
    }

    pub fn pattern_scan_bytes(
        &self,
        pattern: &[u8],
        mask: &str,
        start_addr: Option<usize>,
        end_addr: Option<usize>,
    ) -> Result<Option<usize>, Error> {
        let module_base = self.get_base_address()?;
        let module_size = self.get_base_size()?;
        let start = start_addr.unwrap_or(module_base);
        let end = end_addr.unwrap_or(module_base + module_size);

        #[cfg(target_os = "windows")]
        unsafe {
            let mut scan_addr = start;
            let mut mem_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

            while scan_addr < end {
                if VirtualQueryEx(
                    self.handle,
                    Some(scan_addr as *const _),
                    &mut mem_info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                ) == 0
                {
                    break;
                }

                if mem_info.State == MEM_COMMIT
                    && (mem_info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0
                {
                    let base = mem_info.BaseAddress as usize;
                    let mut size = mem_info.RegionSize;

                    if base + size > end {
                        size = end - base;
                    }

                    if let Some(match_addr) =
                        search_memory_region_windows(self.handle, base, size, &pattern, &mask)
                    {
                        return Ok(Some(match_addr));
                    }
                }

                scan_addr = mem_info.BaseAddress as usize + mem_info.RegionSize;
            }

            Ok(None)
        }

        #[cfg(target_os = "macos")]
        unsafe {
            let mut address = start as mach_vm_address_t;
            let end_addr = end as mach_vm_address_t;

            while address < end_addr {
                let mut size: mach_vm_size_t = 0;
                let mut info: vm_region_basic_info_data_64_t = std::mem::zeroed();
                let mut info_count = VM_REGION_BASIC_INFO_COUNT_64;
                let mut object_name: mach_port_t = MACH_PORT_NULL;

                if mach_vm_region(
                    self.task,
                    &mut address,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    &mut info as *mut _ as *mut i32,
                    &mut info_count,
                    &mut object_name,
                ) != KERN_SUCCESS
                {
                    break;
                }

                if info.protection & (VM_PROT_READ | VM_PROT_EXECUTE) != 0 {
                    let scan_size = if address + size > end_addr {
                        (end_addr - address) as mach_vm_size_t
                    } else {
                        size
                    };

                    if let Some(match_addr) =
                        search_memory_region_macos(self.task, address, scan_size, &pattern, &mask)
                    {
                        return Ok(Some(match_addr));
                    }
                }

                address += size;
            }

            Ok(None)
        }
    }
}



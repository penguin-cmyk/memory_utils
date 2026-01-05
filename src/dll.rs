#![cfg(target_os = "windows")]

use std::{
    io::Error,
    ffi::{CString, OsStr},
    os::windows::ffi::OsStrExt,
    ptr::{copy_nonoverlapping, null_mut},
};

use winapi::{
    shared::minwindef::*,
    um::{
        libloaderapi::{FreeLibrary, GetProcAddress, LoadLibraryA, LoadLibraryW},
        memoryapi::{VirtualAlloc, VirtualProtect},
        winnt::*,
    },
};
#[derive(Clone)]
pub struct DllHandle {
    pub module: HMODULE,
    pub path: String,
}
unsafe impl Send for DllHandle {}
unsafe impl Sync for DllHandle {}

impl DllHandle {
    /// Loads a DLL using an ANSI path string.
    ///
    /// # Arguments
    /// - `path`: Path to the DLL (e.g., `"C:\\MyDLL.dll"`).
    ///
    /// # Returns
    /// - `Ok(DllHandle)`: A handle to the loaded DLL.
    /// - `Err(Error)`: If loading fails.
    pub fn new(path: &str) -> Result<DllHandle, Error> {
        unsafe {
            let c_path = CString::new(path)?;
            let handle = LoadLibraryA(c_path.as_ptr());
            if handle.is_null() {
                return Err(Error::last_os_error());
            }

            Ok(Self { path: path.to_string(), module: handle })
        }
    }

    /// Loads a DLL using a UTF-16 wide string path.
    ///
    /// # Arguments
    /// - `path`: Path to the DLL (e.g., `"C:\\MyDLL.dll"`).
    ///
    /// # Returns
    /// - `Ok(DllHandle)`: A handle to the loaded DLL.
    /// - `Err(Error)`: If loading fails.
    pub fn new_wide(path: &str) -> Result<Self, Error> {
        unsafe {
            let wide: Vec<u16> = OsStr::new(path)
                .encode_wide()
                .chain(Some(0))
                .collect();

            let handle = LoadLibraryW(wide.as_ptr());
            if handle.is_null() {
                return Err(Error::last_os_error())
            }
            Ok(Self { module: handle, path: path.to_string() })
        }
    }

    /// Retrieves a raw pointer to a procedure in the loaded DLL.
    ///
    /// # Arguments
    /// - `name`: Name of the exported function.
    ///
    /// # Returns
    /// - `Ok(FARPROC)`: Pointer to the procedure.
    /// - `Err(Error)`: If the procedure is not found.
    pub fn get_proc(&self, name: &str) -> Result<FARPROC, Error> {
        unsafe {
            let c_name = CString::new(name)?;
            let proc = GetProcAddress(self.module, c_name.as_ptr());
            if proc.is_null() {
                return Err(Error::last_os_error());
            }
            Ok(proc)
        }
    }

    /// Retrieves a typed function pointer from the DLL.
    ///
    /// # Arguments
    /// - `name`: Name of the exported function.
    ///
    /// # Returns
    /// - `Ok<T>`: Function pointer of type `T`.
    /// - `Err(Error)`: If retrieval fails.
    ///
    /// # Safety
    /// The caller must ensure the type `T` matches the actual function signature.
    ///
    /// # Example
    /// ```rust
    /// # use winapi::shared::ntdef::{NTSTATUS, ULONG};
    /// # use memory_utils::dll::DllHandle;
    /// # use winapi::um::winnt::{ HANDLE };
    /// let dll = DllHandle::new("ntdll.dll").unwrap();
    /// type NtReadVirtualMemory = unsafe extern "system" fn(
    ///     ProcessHandle: HANDLE,
    ///     BaseAddress: *const std::ffi::c_void,
    ///     Buffer: *mut std::ffi::c_void,
    ///     NumberOfBytesToRead: ULONG,
    ///     NumberOfBytesReaded: *mut ULONG,
    /// ) -> NTSTATUS;
    /// let nt_read: NtReadVirtualMemory = dll.get_function("NtReadVirtualMemory")?;
    /// ```
    pub fn get_function<T: Copy + 'static>(&self, name: &str) -> Result<T, Error> {
        unsafe {
            let proc = self.get_proc(name)?;
            union Transmute<T: Copy> {
                from: FARPROC,
                to: std::mem::ManuallyDrop<T>,
            }
            let t = Transmute { from: proc };
            Ok(std::mem::ManuallyDrop::into_inner(t.to))
        }
    }

    /// Checks whether the DLL is currently loaded.
    ///
    /// # Returns
    /// - `true` if loaded.
    /// - `false` otherwise.
    pub fn is_loaded(&self) -> bool {
        !self.module.is_null()
    }

    /// Unloads the loaded DLL from memory.
    ///
    /// # Returns
    /// - `true` if successfully unloaded.
    /// - `false` if already unloaded or failed.
    ///
    pub fn unload(&mut self) -> bool {
        unsafe {
            if self.is_loaded() {
                let result = FreeLibrary(self.module);
                self.module = null_mut();

                return result != 0
            }
            false
        }
    }
    /// Hooks a function inside the loaded DLL by writing a 14-byte jump stub.
    ///
    /// # Arguments
    /// - `name`: The name of the function to hook
    /// - `new_func`: Pointer to the new function that will replace the original
    ///
    /// # Returns
    /// - The original function pointer in the form of a trampoline (jump-back stub)
    ///
    /// # Memory Layout
    ///
    /// ```text
    /// [Before Hook]
    /// Address        Bytes                   Disassembly
    /// ────────────   ────────────────────    ──────────────────────────
    /// 0x10000000     55 8B EC                push ebp; mov ebp, esp
    /// 0x10000003     83 EC 08                sub esp, 8
    ///
    /// [After Hook]
    /// Address        Bytes                   Disassembly
    /// ────────────   ────────────────────    ──────────────────────────
    /// 0x10000000     48 B8 <addr>            mov rax, 0x1234567812345678
    /// 0x1000000A     FF E0                   jmp rax
    /// 0x1000000C     CC CC                   int3 (padding)
    ///
    /// [Technical Breakdown]
    /// Offset  Size   Description
    /// ──────  ─────  ───────────────────────────────
    /// +0      2      MOV RAX, opcode (0x48 0xB8)
    /// +2      8      Absolute address to jump to
    /// +10     2      JMP RAX opcode (0xFF 0xE0)
    /// +12     2      INT3 (padding)
    /// ```
    pub fn hook_function(&self, name: &str, new_func: FARPROC) -> Result<FARPROC, Error> {
        unsafe {
            let original = self.get_proc(name)?;

            let mut old_protection = 0;
            if VirtualProtect(
                original as _,
                14, // Sized needed for the hook
                PAGE_EXECUTE_READWRITE,
                &mut old_protection,
            ) == 0 { return Err(Error::last_os_error()) }

            let mut original_bytes = [0u8; 14];
            copy_nonoverlapping(old_protection as *const u8, original_bytes.as_mut_ptr(), 14);

            let mut jump: [u8; 14] = [
                0x48, 0xB8, // MOV RAX, imm64
                0, 0, 0, 0, 0, 0, 0, 0, // Address placeholder
                0xFF, 0xE0, // JMP RAX
                0xCC, 0xCC // Padding
            ];

            let target = new_func as u64;
            jump[2..10].copy_from_slice(&target.to_ne_bytes());

            copy_nonoverlapping(jump.as_ptr(), original as *mut u8, 14);

            VirtualProtect(original as _, 14, old_protection, &mut old_protection);

            let trampoline = self.create_trampoline(original,&original_bytes)?;
            Ok(trampoline)
        }
    }

    unsafe fn create_trampoline(&self, original: FARPROC, original_bytes: &[u8]) -> Result<FARPROC, Error> {
        let trampoline_size = original_bytes.len() + 14; // Original bytes + jump back
        let trampoline = VirtualAlloc(
            null_mut(),
            trampoline_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if trampoline.is_null() {
            return Err(Error::last_os_error());
        }

        copy_nonoverlapping(original_bytes.as_ptr(), trampoline as *mut u8, original_bytes.len());

        let mut jump_back: [u8; 14] = [
            0x48, 0xB8, // MOV RAX, imm64
            0, 0, 0, 0, 0, 0, 0, 0, // Address placeholder
            0xFF, 0xE0, // JMP RAX
            0xCC, 0xCC  // Padding
        ];

        let return_addr = (original as u64).wrapping_add(original_bytes.len() as u64);
        jump_back[2..10].copy_from_slice(&return_addr.to_ne_bytes());

        copy_nonoverlapping(jump_back.as_ptr(), trampoline.add(original_bytes.len()) as *mut u8, 14);

        let mut old_protect = 0;
        VirtualProtect(
            trampoline,
            trampoline_size,
            PAGE_EXECUTE_READ,
            &mut old_protect
        );

        Ok(trampoline as FARPROC)
    }

}


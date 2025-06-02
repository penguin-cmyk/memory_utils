# memory_utils

![Alt Text](https://raw.githubusercontent.com/penguin-cmyk/memory_utils/refs/heads/master/must_logo.png)
A simple and safe(ish) Rust library for reading and writing memory of external Windows processes. Useful for building tools like trainers, debuggers, and analyzers.

Please note that this is project is in its early stages so bugs may occur.

To get the cargo crate check out [this link](https://crates.io/crates/memory_utils)

A simple project I made using this library is a walk speed modifier. You can find it [here](https://github.com/penguin-cmyk/walkspeed-modifier/tree/main)

--------
## Features

- Read and write memory of external processes.
- Get process ID (PID) by process name.
- Suspend, resume, and terminate threads or processes.
- Read null-terminated strings from memory.
- Query memory pages using `VirtualQueryEx`.
- Built on top of WinAPI.
--------
## Changelogs
* `0.1.2`: 
  * Fixed Process::pid() error "STATUS_HEAP_CORRUPTION" which was caused by a bad conversion from cstring into rust string
* `0.1.4`:
  * Fixed general pattern scanning ( added more protection checks, and fixed stuck in a loop or not finding it)
* `0.1.6`:
  * Added `process.get_module` and `process.get_base_address`,
  * Removed duplicated `mbi.Protect ==  PAGE_READWRITE` check from `pattern_scan` which should speed it up a bit.
* `0.1.8`:
  * Added every protection option to `ProtectOptions`, Added `process.get_protection`
* `0.1.9 & 0.1.10`:
  * Fixed accidental mistake of doing `addr as LPVOID` instead of `addr as LCPVOID`
* `0.1.11`:
  * Fixed `process.get_threads()` since it had `TH32CS_SNAPPROCESS` instead of `TH32CS_SNAPTHREAD`
* `0.1.12`:
  * Fixed `process.get_thread_context()` error due to invalid handling of the returned error (`?` -> `is_err()` )
* `0.1.13`:
  * Optimized `process.find_pattern_str` and `process.pattern_scan` by using the Boyer-Moore-Horspool algorithm in `find_pattern`
* `0.1.14`:
  * Fixed `process.read_stack`, 
  * Added `process.pe_headers`
* `0.1.15`: 
  * Made  `process.sanitize_bytes` public,
  * Added `process.get_modules`, 
  * Added `process.is_valid_address`, 
  * Added `process.allocate`, 
  * Added `process.trampoline_hook`
  * Added `process.place_absolute_jmp`
* `0.1.17`:
  * Added `process.write_bytes` 
* `0.1.18`:
  * Made `pid` in `Process` public
  * Added `handle` to the `Process` struct (so that it doesn't open a new handle everytime. This is due to performance)
* `0.1.19`:
  * The `Process` struct can now be safely shared between threads 
  * Implemented `clone` for `Process`

-------
* `0.2.0`
  * Added `DllLib` *(memory_utils::dll)*, seperate from the main process 

--------
## Example

```rust
use memory_utils::process::Process;

fn main() {
    // Get the PID of the target process
    let pid = Process::pid("RobloxPlayerBeta.exe").expect("Failed to find process");

    // Create a new process handle
    let process = Process::new(pid);

    // Read an integer from an address
    let value: i32 = process.read_memory(0x00ABCDEF).expect("Failed to read memory");

    // Write a new value
    process.write_memory(0x00ABCDEF, &1337).expect("Failed to write memory");

    // Read a string (null-terminated)
    let name = process.read_string(0x00FFEEDD).expect("Failed to read string");

    println!("Read value: {}, Read string: {}", value, name);
}
```
# memory_utils
![Alt Text](https://raw.githubusercontent.com/penguin-cmyk/memory_utils/refs/heads/master/must_logo.png)

A simple and safe(ish) Rust library for reading and writing memory of external Windows processes. Useful for building tools like trainers, debuggers, and analyzers.

Please note that this is project is in its early stages so bugs may occur.

To get the cargo crate check out [this link](https://crates.io/crates/memory_utils)
## Features

- Read and write memory of external processes.
- Get process ID (PID) by process name.
- Suspend, resume, and terminate threads or processes.
- Read null-terminated strings from memory.
- Query memory pages using `VirtualQueryEx`.
- Built on top of WinAPI.

## Changelogs
* `0.1.2` - Fixed Process::pid() error "STATUS_HEAP_CORRUPTION" which was caused by a bad conversion from cstring into rust string
* `0.1.4` - Fixed general pattern scanning ( added more protection checks, and fixed stuck in a loop or not finding it)
* `0.1.6` - Added `process.get_module` and `process.get_base_address` , Removed duplicated `mbi.Protect ==  PAGE_READWRITE` check from `pattern_scan` which should speed it up a bit.
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

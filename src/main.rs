//! Telemetry-only memory test for Windows.
//! - Allocates RW memory
//! - Writes benign bytes
//! - Flips to RX (PAGE_EXECUTE_READ), then back to RW
//! - Never executes from that region

#[cfg(windows)]
use anyhow::{bail, Result};
#[cfg(windows)]
use core::ffi::c_void;
#[cfg(windows)]
use std::{ptr, slice};
#[cfg(windows)]
use windows::Win32::Foundation::BOOL;
#[cfg(windows)]
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};

#[cfg(windows)]
fn main() -> Result<()> {
    unsafe {
        // 1) Reserve+commit 4 KiB, RW
        let size: usize = 4096;
        let ptr = VirtualAlloc(
            ptr::null_mut(),                   // lpAddress (let the OS choose)
            size,                              // dwSize
            MEM_COMMIT | MEM_RESERVE,          // flAllocationType
            PAGE_READWRITE,                    // flProtect
        );

        if ptr.is_null() {
            bail!("VirtualAlloc failed (null pointer returned)");
        }
        println!("[+] Allocated {} bytes at {:p} (RW)", size, ptr);

        // 2) Treat it as a byte slice and write benign data
        let buf = slice::from_raw_parts_mut(ptr as *mut u8, size);
        for (i, b) in buf.iter_mut().enumerate().take(64) {
            *b = (b'A' + (i as u8 % 26)) as u8; // just some printable bytes
        }
        println!("[+] Wrote {} bytes of benign data", 64);

        // 3) Flip protection to RX (this is what many detections key on)
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        let ok: BOOL = VirtualProtect(
            ptr as *const c_void,
            size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );
        if !ok.as_bool() {
            // Clean up before bailing
            VirtualFree(ptr as *mut c_void, 0, MEM_RELEASE);
            bail!("VirtualProtect RW->RX failed");
        }
        println!(
            "[+] Protection changed RW -> RX (old={:#x})",
            old_protect.0
        );

        // 4) Immediately flip back to RW (no execution happens)
        let mut old2 = PAGE_PROTECTION_FLAGS(0);
        let ok2: BOOL = VirtualProtect(ptr as *const c_void, size, PAGE_READWRITE, &mut old2);
        if !ok2.as_bool() {
            VirtualFree(ptr as *mut c_void, 0, MEM_RELEASE);
            bail!("VirtualProtect RX->RW failed");
        }
        println!("[+] Protection reverted RX -> RW (old={:#x})", old2.0);

        // 5) Free
        let freed = VirtualFree(ptr as *mut c_void, 0, MEM_RELEASE);
        if !freed.as_bool() {
            bail!("VirtualFree failed");
        }
        println!("[+] Freed region and exiting cleanly.");
    }

    Ok(())
}

#[cfg(not(windows))]
fn main() {
    println!("This example is intended to run on Windows.");
}

#![allow(non_camel_case_types)]

use crate::engine::Engine;
use crate::ffi;
use crate::result::{Error, Result};
use bitflags::bitflags;
use core::ffi::c_void;
use std::ops::RangeInclusive;
use std::ptr::null_mut;
use std::ptr::slice_from_raw_parts;

pub type MemAddress = u64;

pub type MemValue = u64;

pub type MemRange = RangeInclusive<MemAddress>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(u32)]
pub enum MemAccess {
    NONE = 0 as _,
    READ = ffi::UC_MEM_READ as _,
    WRITE = ffi::UC_MEM_WRITE as _,
    FETCH = ffi::UC_MEM_FETCH as _,
    READ_UNMAPPED = ffi::UC_MEM_READ_UNMAPPED as _,
    WRITE_UNMAPPED = ffi::UC_MEM_WRITE_UNMAPPED as _,
    FETCH_UNMAPPED = ffi::UC_MEM_FETCH_UNMAPPED as _,
    WRITE_PROT = ffi::UC_MEM_WRITE_PROT as _,
    READ_PROT = ffi::UC_MEM_READ_PROT as _,
    FETCH_PROT = ffi::UC_MEM_FETCH_PROT as _,
    READ_AFTER = ffi::UC_MEM_READ_AFTER as _,
}

bitflags! {
    /// All type of memory accesses for ``hook_mem``
    pub struct MemHook: u32 {
        const NONE = 0;

        const READ_UNMAPPED = ffi::UC_HOOK_MEM_READ_UNMAPPED as _;
        const WRITE_UNMAPPED = ffi::UC_HOOK_MEM_WRITE_UNMAPPED as _;
        const FETCH_UNMAPPED = ffi::UC_HOOK_MEM_FETCH_UNMAPPED as _;
        const READ_PROT = ffi::UC_HOOK_MEM_READ_PROT as _;
        const WRITE_PROT = ffi::UC_HOOK_MEM_WRITE_PROT as _;
        const FETCH_PROT = ffi::UC_HOOK_MEM_FETCH_PROT as _;
        const READ = ffi::UC_HOOK_MEM_READ as _;
        const WRITE = ffi::UC_HOOK_MEM_WRITE as _;
        const FETCH = ffi::UC_HOOK_MEM_FETCH as _;
        const READ_AFTER = ffi::UC_HOOK_MEM_READ_AFTER as _;

        const READ_INVALID = Self::READ_UNMAPPED.bits | Self::READ_PROT.bits;
        const WRITE_INVALID = Self::WRITE_UNMAPPED.bits | Self::WRITE_PROT.bits;
        const FETCH_INVALID = Self::FETCH_UNMAPPED.bits | Self::FETCH_PROT.bits;
        const UNMAPPED = Self::READ_UNMAPPED.bits | Self::WRITE_UNMAPPED.bits | Self::FETCH_UNMAPPED.bits;
        const PROT = Self::READ_PROT.bits | Self::WRITE_PROT.bits | Self::FETCH_PROT.bits;
        const INVALID =  Self::UNMAPPED.bits | Self::PROT.bits;
        const VALID = Self::READ.bits | Self::WRITE.bits | Self::FETCH.bits;
        const ALL = Self::INVALID.bits | Self::VALID.bits;
    }

    /// Allowed memory access types
    pub struct MemProt: u32 {
        const NONE = ffi::UC_PROT_NONE as _;
        const READ = ffi::UC_PROT_READ as _;
        const WRITE = ffi::UC_PROT_WRITE as _;
        const EXEC = ffi::UC_PROT_EXEC as _;
        const ALL = ffi::UC_PROT_ALL as _;
    }
}

/// Memory region mapped by *_map functions
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct MemRegion {
    pub range: MemRange,
    pub prot: MemProt,
}

impl MemAccess {
    pub(crate) fn from_callback(mem_type: ffi::uc_mem_type) -> Self {
        match mem_type {
            ffi::UC_MEM_READ => MemAccess::READ,
            ffi::UC_MEM_WRITE => MemAccess::WRITE,
            ffi::UC_MEM_FETCH => MemAccess::FETCH,
            ffi::UC_MEM_READ_UNMAPPED => MemAccess::READ_UNMAPPED,
            ffi::UC_MEM_WRITE_UNMAPPED => MemAccess::WRITE_UNMAPPED,
            ffi::UC_MEM_FETCH_UNMAPPED => MemAccess::FETCH_UNMAPPED,
            ffi::UC_MEM_WRITE_PROT => MemAccess::WRITE_PROT,
            ffi::UC_MEM_READ_PROT => MemAccess::READ_PROT,
            ffi::UC_MEM_FETCH_PROT => MemAccess::FETCH_PROT,
            ffi::UC_MEM_READ_AFTER => MemAccess::READ_AFTER,
            _ => MemAccess::NONE,
        }
    }
}

impl MemRegion {
    fn from_raw(raw: ffi::uc_mem_region) -> Self {
        let range = raw.begin..=raw.end;
        let prot = MemProt::from_bits_truncate(raw.perms);
        Self { range, prot }
    }

    pub(crate) unsafe fn from_raw_vec(
        regions: *const ffi::uc_mem_region,
        count: usize,
    ) -> Vec<Self> {
        (*slice_from_raw_parts(regions, count))
            .into_iter()
            .map(|&raw| Self::from_raw(raw))
            .collect()
    }
}

impl<'a, D> Engine<'a, D> {
    /// Returns a vector with the memory regions that are mapped in the emulator.
    pub fn mem_regions(&self) -> Result<Vec<MemRegion>> {
        let mut regions = null_mut();
        let mut count = 0;
        unsafe {
            Error::check(ffi::uc_mem_regions(self.uc(), &mut regions, &mut count))?;
            let result = MemRegion::from_raw_vec(regions, count as usize);
            ffi::uc_free(regions as *mut _);
            Ok(result)
        }
    }

    /// Read a range of bytes from memory at the specified address.
    ///
    /// The caller has to ensure sizes matches the memory location
    pub unsafe fn mem_read_raw(
        &self,
        address: MemAddress,
        bytes: *mut c_void,
        size: usize,
    ) -> Result<()> {
        Error::check(ffi::uc_mem_read(self.uc(), address, bytes, size))
    }

    /// Write a range of bytes from memory at the specified address.
    ///
    /// The caller has to ensure sizes matches the memory location
    pub unsafe fn mem_write_raw(
        &mut self,
        address: MemAddress,
        bytes: *const c_void,
        size: usize,
    ) -> Result<()> {
        Error::check(ffi::uc_mem_write(self.uc(), address, bytes, size))
    }

    /// Read a range of bytes from memory at the specified address.
    pub fn mem_read(&self, address: MemAddress, data: &mut [u8]) -> Result<()> {
        let bytes = data.as_ptr() as *mut _;
        let size = data.len();
        unsafe { self.mem_read_raw(address, bytes, size) }
    }

    /// Write a range of bytes from memory at the specified address.
    pub fn mem_write(&mut self, address: MemAddress, data: &[u8]) -> Result<()> {
        let bytes = data.as_ptr() as *const _;
        let size = data.len();
        unsafe { self.mem_write_raw(address, bytes, size) }
    }

    /// Map a memory region in the emulator at the specified address.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::Arg`.
    /// `size` must be a multiple of 4kb or this will return `Error::Arg`.
    pub fn mem_map(&mut self, address: MemAddress, size: usize, prot: MemProt) -> Result<()> {
        let perms = prot.bits() as _;
        unsafe { Error::check(ffi::uc_mem_map(self.uc(), address, size, perms)) }
    }

    /// Unmap a memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::Arg`.
    /// `size` must be a multiple of 4kb or this will return `Error::Arg`.
    pub fn mem_unmap(&mut self, address: MemAddress, size: usize) -> Result<()> {
        unsafe { Error::check(ffi::uc_mem_unmap(self.uc(), address, size)) }
    }

    /// Set the memory permissions for an existing memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::Arg`.
    /// `size` must be a multiple of 4kb or this will return `Error::Arg`.
    pub fn mem_protect(&mut self, address: MemAddress, size: usize, prot: MemProt) -> Result<()> {
        let perms = prot.bits() as _;
        unsafe { Error::check(ffi::uc_mem_protect(self.uc(), address, size, perms)) }
    }

    /// Fills memory with array pattern.
    pub fn mem_fill(&mut self, address: MemAddress, size: usize, with: &[u8]) -> Result<()> {
        let mut cur = address;
        let mut remain = size;
        while remain != 0 {
            let chunk_size = usize::min(with.len(), remain);
            self.mem_write(cur, &with[..chunk_size as usize])?;
            cur += chunk_size as MemAddress;
            remain -= chunk_size;
        }
        Ok(())
    }
}

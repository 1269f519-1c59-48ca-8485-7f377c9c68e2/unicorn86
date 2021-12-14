#![allow(non_snake_case)]
use crate::ffi;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Error {
    /// Out-Of-Memory error
    NoMem,
    /// Unsupported architecture
    ArchMode,
    /// Invalid handle
    Handle,
    /// Invalid/unsupported mode
    Mode,
    /// Unsupported version
    Version,
    /// Quit emulation due to ``MemAccess::READ_UNMAPPED``
    ReadUnmapped,
    /// Quit emulation due to ``MemAccess::WRITE_UNMAPPED``
    WriteUnmapped,
    /// Quit emulation due to ``MemAccess::FETCH_UNMAPPED``
    FetchUnmapped,
    /// Invalid hook type
    Hook,
    /// Quit emulation due to invalid instruction
    InsnInvalid,
    /// Invalid memory mapping
    Map,
    /// Quit emulation due to ``MemAccess::WRITE_PROT`` violation
    WriteProt,
    /// Quit emulation due to ``MemAccess::READ_PROT`` violation
    ReadProt,
    /// Quit emulation due to ``MemAccess::FETCH_PROT`` violation
    FetchProt,
    /// Inavalid argument provided to a function
    Arg,
    /// Unaligned read
    ReadUnaligned,
    /// Unaligned write
    WriteUnaligned,
    /// Unaligned fetch
    FetchUnaligned,
    /// Hook for this event already existed
    HookExist,
    /// Insufficient resource
    Resource,
    /// Unhandled CPU exception
    Exception,
    /// Other unbound errors
    Unknown(u32),
}

pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    pub(crate) fn check(err: ffi::uc_err) -> Result<()> {
        match err {
            ffi::UC_ERR_OK => Ok(()),
            ffi::UC_ERR_NOMEM => Err(Error::NoMem),
            ffi::UC_ERR_ARCH => Err(Error::ArchMode),
            ffi::UC_ERR_HANDLE => Err(Error::Handle),
            ffi::UC_ERR_MODE => Err(Error::Mode),
            ffi::UC_ERR_VERSION => Err(Error::Version),
            ffi::UC_ERR_READ_UNMAPPED => Err(Error::ReadUnmapped),
            ffi::UC_ERR_WRITE_UNMAPPED => Err(Error::WriteUnmapped),
            ffi::UC_ERR_FETCH_UNMAPPED => Err(Error::FetchUnmapped),
            ffi::UC_ERR_HOOK => Err(Error::Hook),
            ffi::UC_ERR_INSN_INVALID => Err(Error::InsnInvalid),
            ffi::UC_ERR_MAP => Err(Error::Map),
            ffi::UC_ERR_WRITE_PROT => Err(Error::WriteProt),
            ffi::UC_ERR_READ_PROT => Err(Error::ReadProt),
            ffi::UC_ERR_FETCH_PROT => Err(Error::FetchProt),
            ffi::UC_ERR_ARG => Err(Error::Arg),
            ffi::UC_ERR_READ_UNALIGNED => Err(Error::ReadUnaligned),
            ffi::UC_ERR_WRITE_UNALIGNED => Err(Error::WriteUnaligned),
            ffi::UC_ERR_FETCH_UNALIGNED => Err(Error::FetchUnaligned),
            ffi::UC_ERR_HOOK_EXIST => Err(Error::HookExist),
            ffi::UC_ERR_RESOURCE => Err(Error::Resource),
            ffi::UC_ERR_EXCEPTION => Err(Error::Exception),
            unknown => Err(Error::Unknown(unknown as u32)),
        }
    }
}

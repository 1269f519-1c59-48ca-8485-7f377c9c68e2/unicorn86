use crate::ffi;
use crate::mem::MemAddress;
use crate::result::{Error, Result};
use crate::{HookID, IHook};
use std::cell::UnsafeCell;
use std::collections::BTreeMap;
use std::ptr::null_mut;
use std::rc::{Rc, Weak};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(u32)]
pub enum CPU {
    DEFAULT = u32::MAX,
    QEMU64 = ffi::UC_CPU_X86_QEMU64 as _,
    PHENOM = ffi::UC_CPU_X86_PHENOM as _,
    CORE2DUO = ffi::UC_CPU_X86_CORE2DUO as _,
    KVM64 = ffi::UC_CPU_X86_KVM64 as _,
    QEMU32 = ffi::UC_CPU_X86_QEMU32 as _,
    KVM32 = ffi::UC_CPU_X86_KVM32 as _,
    COREDUO = ffi::UC_CPU_X86_COREDUO as _,
    I486 = ffi::UC_CPU_X86_486 as _,
    PENTIUM = ffi::UC_CPU_X86_PENTIUM as _,
    PENTIUM2 = ffi::UC_CPU_X86_PENTIUM2 as _,
    PENTIUM3 = ffi::UC_CPU_X86_PENTIUM3 as _,
    ATHLON = ffi::UC_CPU_X86_ATHLON as _,
    N270 = ffi::UC_CPU_X86_N270 as _,
    CONROE = ffi::UC_CPU_X86_CONROE as _,
    PENRYN = ffi::UC_CPU_X86_PENRYN as _,
    NEHALEM = ffi::UC_CPU_X86_NEHALEM as _,
    WESTMERE = ffi::UC_CPU_X86_WESTMERE as _,
    SANDYBRIDGE = ffi::UC_CPU_X86_SANDYBRIDGE as _,
    IVYBRIDGE = ffi::UC_CPU_X86_IVYBRIDGE as _,
    HASWELL = ffi::UC_CPU_X86_HASWELL as _,
    BROADWELL = ffi::UC_CPU_X86_BROADWELL as _,
    SKYLAKE_CLIENT = ffi::UC_CPU_X86_SKYLAKE_CLIENT as _,
    SKYLAKE_SERVER = ffi::UC_CPU_X86_SKYLAKE_SERVER as _,
    CASCADELAKE_SERVER = ffi::UC_CPU_X86_CASCADELAKE_SERVER as _,
    COOPERLAKE = ffi::UC_CPU_X86_COOPERLAKE as _,
    ICELAKE_CLIENT = ffi::UC_CPU_X86_ICELAKE_CLIENT as _,
    ICELAKE_SERVER = ffi::UC_CPU_X86_ICELAKE_SERVER as _,
    DENVERTON = ffi::UC_CPU_X86_DENVERTON as _,
    SNOWRIDGE = ffi::UC_CPU_X86_SNOWRIDGE as _,
    KNIGHTSMILL = ffi::UC_CPU_X86_KNIGHTSMILL as _,
    OPTERON_G1 = ffi::UC_CPU_X86_OPTERON_G1 as _,
    OPTERON_G2 = ffi::UC_CPU_X86_OPTERON_G2 as _,
    OPTERON_G3 = ffi::UC_CPU_X86_OPTERON_G3 as _,
    OPTERON_G4 = ffi::UC_CPU_X86_OPTERON_G4 as _,
    OPTERON_G5 = ffi::UC_CPU_X86_OPTERON_G5 as _,
    EPYC = ffi::UC_CPU_X86_EPYC as _,
    DHYANA = ffi::UC_CPU_X86_DHYANA as _,
    EPYC_ROME = ffi::UC_CPU_X86_EPYC_ROME as _,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(u32)]
pub enum Mode {
    X16 = ffi::UC_MODE_16 as _,
    X32 = ffi::UC_MODE_32 as _,
    X64 = ffi::UC_MODE_64 as _,
}

pub(crate) struct EngineInner<'a, D> {
    pub uc: *mut ffi::uc_engine,
    pub hooks: BTreeMap<HookID, Box<dyn IHook<'a> + 'a>>,
    pub data: D,
}

impl<'a, D> Drop for EngineInner<'a, D> {
    fn drop(&mut self) {
        if !self.uc.is_null() {
            unsafe {
                ffi::uc_close(self.uc);
            }
        }
        self.uc = null_mut();
    }
}

/// A Unicorn emulator instance.
pub struct Engine<'a, D = ()> {
    pub(crate) inner: Rc<UnsafeCell<EngineInner<'a, D>>>,
}

impl<'a> Engine<'a, ()> {
    /// Create a new instance of the unicorn engine.
    pub fn new(cpu: CPU, mode: Mode) -> Result<Self> {
        Self::new_with_data(cpu, mode, ())
    }
}

impl<'a, D: 'a> Engine<'a, D> {
    /// Create a new instance of the unicorn engine with user data.
    pub fn new_with_data(cpu: CPU, mode: Mode, data: D) -> Result<Self> {
        let mut uc = null_mut();
        unsafe {
            Error::check(ffi::uc_open(ffi::UC_ARCH_X86, mode as u32 as _, &mut uc))?;
        }
        let result = Engine {
            inner: Rc::new(UnsafeCell::new(EngineInner {
                uc,
                hooks: Default::default(),
                data,
            })),
        };
        if cpu != CPU::DEFAULT {
            unsafe {
                Error::check(ffi::uc_ctl(
                    uc,
                    UC_CTL(ffi::UC_CTL_CPU_MODEL, 1, false, true),
                    cpu as u32,
                ))?;
            }
        }
        Ok(result)
    }
}

impl<'a, D> Engine<'a, D> {
    pub(crate) unsafe fn inner(&self) -> &EngineInner<'a, D> {
        unsafe { self.inner.get().as_ref().unwrap_unchecked() }
    }

    pub(crate) unsafe fn inner_mut(&mut self) -> &mut EngineInner<'a, D> {
        unsafe { self.inner.get().as_mut().unwrap_unchecked() }
    }

    pub(crate) unsafe fn inner_weak(&self) -> Weak<UnsafeCell<EngineInner<'a, D>>> {
        unsafe { Rc::<_>::downgrade(&self.inner) }
    }

    pub(crate) unsafe fn uc(&self) -> *mut ffi::uc_engine {
        unsafe { self.inner().uc }
    }

    /// Return whatever data was passed during initialization.
    ///
    /// For an example, have a look at `utils::init_emu_with_heap` where
    /// a struct is passed which is used for a custom allocator.
    #[must_use]
    pub fn get_data(&self) -> &D {
        unsafe { &self.inner().data }
    }

    /// Return a mutable reference to whatever data was passed during initialization.
    #[must_use]
    pub fn get_data_mut(&mut self) -> &mut D {
        unsafe { &mut self.inner_mut().data }
    }

    /// Emulate machine code for a specified duration.
    ///
    /// `begin` is the address where to start the emulation. The emulation stops if `until`
    /// is hit. `timeout` specifies a duration in microseconds after which the emulation is
    /// stopped (infinite execution if set to 0). `count` is the maximum number of instructions
    /// to emulate (emulate all the available instructions if set to 0).
    pub fn emu_start(
        &mut self,
        begin: MemAddress,
        until: MemAddress,
        timeout: u64,
        count: usize,
    ) -> Result<()> {
        unsafe { Error::check(ffi::uc_emu_start(self.uc(), begin, until, timeout, count)) }
    }

    /// Stop the emulation.
    ///
    /// This is usually called from callback function in hooks.
    /// NOTE: For now, this will stop the execution only after the current block.
    pub fn emu_stop(&mut self) -> Result<()> {
        unsafe { Error::check(ffi::uc_emu_stop(self.uc())) }
    }

    /// Get mode.
    pub fn ctl_get_mode(&self) -> Result<Mode> {
        let mut mode: ffi::uc_mode = Default::default();
        unsafe {
            Error::check(ffi::uc_ctl(
                self.uc(),
                UC_CTL(ffi::UC_CTL_UC_MODE, 1, true, false),
                &mut mode as *mut _,
            ))?;
        }
        match mode {
            ffi::UC_MODE_16 => Ok(Mode::X16),
            ffi::UC_MODE_32 => Ok(Mode::X32),
            ffi::UC_MODE_64 => Ok(Mode::X64),
            _ => Err(Error::ArchMode),
        }
    }
}

const fn UC_CTL(
    type_: ffi::uc_control_type,
    nr: u32,
    read: bool,
    write: bool,
) -> ffi::uc_control_type {
    let mut result = type_ as u32;
    result |= nr << 26;
    if read {
        result |= 2 << 30;
    }
    if write {
        result |= 1 << 30;
    }
    result as ffi::uc_control_type
}

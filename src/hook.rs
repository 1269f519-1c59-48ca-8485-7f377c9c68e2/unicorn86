use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::marker::PhantomPinned;
use std::rc::Weak;

use crate::engine::Engine;
use crate::mem::{MemAccess, MemAddress, MemHook, MemRange};
use crate::result::{Error, Result};
use crate::{ffi, EngineInner, MemValue};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(transparent)]
pub struct HookID(usize);

struct Hook<'a, D: 'a, CB: 'a> {
    pub unicorn: Weak<UnsafeCell<EngineInner<'a, D>>>,
    pub callback: CB,
    pub _pinned: PhantomPinned,
}

pub(crate) trait IHook<'a> {}

impl<'a, D, CB> IHook<'a> for Hook<'a, D, CB> {}

impl<'a, D: 'a> Engine<'a, D> {
    fn hook_add<CB: 'a>(
        &mut self,
        type_: u32,
        trampoline: *mut c_void,
        callback: CB,
        range: Option<MemRange>,
        arg0: u32,
    ) -> Result<HookID> {
        let (begin, end) = match range {
            Some(range) => (*range.start(), *range.end()),
            None => (1, 0),
        };
        let mut hook_id = 0;
        unsafe {
            let mut user_data = Box::new(Hook {
                unicorn: self.inner_weak(),
                callback,
                _pinned: Default::default(),
            });
            Error::check(ffi::uc_hook_add(
                self.uc(),
                &mut hook_id,
                type_ as _,
                trampoline as *const _ as *mut _,
                user_data.as_mut() as *mut _ as _,
                begin,
                end,
                arg0,
            ))?;
            self.inner_mut().hooks.insert(HookID(hook_id), user_data);
        }
        Ok(HookID(hook_id))
    }

    pub fn hook_del(&mut self, hook: HookID) {
        let _ = unsafe { self.inner_mut().hooks.remove(&hook) };
        unsafe { ffi::uc_hook_del(self.uc(), hook.0 as ffi::uc_hook) };
    }

    /// Hook memory access events
    pub fn hook_add_mem<CB: 'a>(
        &mut self,
        callback: CB,
        kind: MemHook,
        range: Option<MemRange>,
    ) -> Result<HookID>
    where
        CB: FnMut(
            /*unicorn:*/ Engine<'a, D>,
            /*mem_access:*/ MemAccess,
            /*address:*/ MemAddress,
            /*size:*/ usize,
            /*value:*/ MemValue,
        ) -> bool,
    {
        self.hook_add(
            kind.bits(),
            Hook::<'a, D, CB>::trampoline_mem as *mut _,
            callback,
            range,
            0,
        )
    }

    pub fn hook_add_code<CB: 'a>(&mut self, callback: CB, range: Option<MemRange>) -> Result<HookID>
    where
        CB: FnMut(
            /*unicorn:*/ Engine<'a, D>,
            /*address:*/ MemAddress,
            /*size:*/ usize,
        ),
    {
        self.hook_add(
            ffi::UC_HOOK_CODE as _,
            Hook::<'a, D, CB>::trampoline_code as *mut _,
            callback,
            range,
            0,
        )
    }

    /// Hooks basic blocks
    pub fn hook_add_block<CB: 'a>(
        &mut self,
        callback: CB,
        range: Option<MemRange>,
    ) -> Result<HookID>
    where
        CB: FnMut(
            /*unicorn:*/ Engine<'a, D>,
            /*address:*/ MemAddress,
            /*size:*/ usize,
        ),
    {
        self.hook_add(
            ffi::UC_HOOK_BLOCK as _,
            Hook::<'a, D, CB>::trampoline_block as *mut _,
            callback,
            range,
            0,
        )
    }

    /// Hook interupts
    pub fn hook_add_intr<CB: 'a>(&mut self, callback: CB, range: Option<MemRange>) -> Result<HookID>
    where
        CB: FnMut(/*unicorn:*/ Engine<'a, D>, /*number:*/ u32),
    {
        self.hook_add(
            ffi::UC_HOOK_INTR as _,
            Hook::<'a, D, CB>::trampoline_intr as *mut _,
            callback,
            range,
            0,
        )
    }

    /// Hook invalid instructions
    pub fn hook_add_insn_invalid<CB: 'a>(
        &mut self,
        callback: CB,
        range: Option<MemRange>,
    ) -> Result<HookID>
    where
        CB: FnMut(/*unicorn:*/ Engine<'a, D>) -> bool,
    {
        self.hook_add(
            ffi::UC_HOOK_INSN_INVALID as _,
            Hook::<'a, D, CB>::trampoline_insn_invalid as *mut _,
            callback,
            range,
            0,
        )
    }

    /// Hook X86 SYSCALl instruction
    pub fn hook_add_insn_syscall<CB: 'a>(
        &mut self,
        callback: CB,
        range: Option<MemRange>,
    ) -> Result<HookID>
    where
        CB: FnMut(/*unicorn:*/ Engine<'a, D>),
    {
        self.hook_add(
            ffi::UC_HOOK_INSN as _,
            Hook::<'a, D, CB>::trampoline_insn_syscall as *mut _,
            callback,
            range,
            ffi::UC_X86_INS_SYSCALL as _,
        )
    }

    /// Hook X86 SYSENTER instruction
    pub fn hook_add_insn_sysenter<CB: 'a>(
        &mut self,
        callback: CB,
        range: Option<MemRange>,
    ) -> Result<HookID>
    where
        CB: FnMut(/*unicorn:*/ Engine<'a, D>),
    {
        self.hook_add(
            ffi::UC_HOOK_INSN as _,
            Hook::<'a, D, CB>::trampoline_insn_sysenter as *mut _,
            callback,
            range,
            ffi::UC_X86_INS_SYSENTER as _,
        )
    }

    /// Hook X86 CPUID instruction
    pub fn hook_add_insn_cpuid<CB: 'a>(
        &mut self,
        callback: CB,
        range: Option<MemRange>,
    ) -> Result<HookID>
    where
        CB: FnMut(/*unicorn:*/ Engine<'a, D>),
    {
        self.hook_add(
            ffi::UC_HOOK_INSN as _,
            Hook::<'a, D, CB>::trampoline_insn_cpuid as *mut _,
            callback,
            range,
            ffi::UC_X86_INS_CPUID as _,
        )
    }

    /// Hook X86 IN instruction
    pub fn hook_add_insn_in<CB: 'a>(
        &mut self,
        callback: CB,
        range: Option<MemRange>,
    ) -> Result<HookID>
    where
        CB: FnMut(/*unicorn:*/ Engine<'a, D>, /*port:*/ u32, /*size:*/ usize) -> u32 + 'a,
    {
        self.hook_add(
            ffi::UC_HOOK_INSN as _,
            Hook::<'a, D, CB>::trampoline_insn_in as *mut _,
            callback,
            range,
            ffi::UC_X86_INS_IN as _,
        )
    }

    /// Hook X86 OUT instruction
    pub fn hook_add_insn_out<CB: 'a>(
        &mut self,
        callback: CB,
        range: Option<MemRange>,
    ) -> Result<HookID>
    where
        CB: FnMut(
            /*unicorn:*/ Engine<'a, D>,
            /*port:*/ u32,
            /*size:*/ usize,
            /*value:*/ u32,
        ),
    {
        self.hook_add(
            ffi::UC_HOOK_INSN as _,
            Hook::<'a, D, CB>::trampoline_insn_out as *mut _,
            callback,
            range,
            ffi::UC_X86_INS_OUT as _,
        )
    }
}

/// Hook memory access
impl<'a, D: 'a, CB: 'a> Hook<'a, D, CB>
where
    CB: FnMut(
        /*unicorn:*/ Engine<'a, D>,
        /*mem_access:*/ MemAccess,
        /*address:*/ MemAddress,
        /*size:*/ usize,
        /*value:*/ MemValue,
    ) -> bool,
{
    unsafe extern "C" fn trampoline_mem(
        _uc: *mut ffi::uc_engine,
        mem_type: ffi::uc_mem_type,
        address: u64,
        size: u32,
        value: u64,
        user_data: &mut Self,
    ) -> bool {
        let unicorn = Engine {
            inner: unsafe { user_data.unicorn.upgrade().unwrap_unchecked() },
        };
        let callback = &mut user_data.callback;
        let mem_access = MemAccess::from_callback(mem_type);
        callback(unicorn, mem_access, address, size as _, value)
    }
}

/// Hook code instructions
impl<'a, D: 'a, CB: 'a> Hook<'a, D, CB>
where
    CB: FnMut(/*unicorn:*/ Engine<'a, D>, /*address:*/ MemAddress, /*size:*/ usize),
{
    unsafe extern "C" fn trampoline_code(
        _uc: *mut ffi::uc_engine,
        address: u64,
        size: u32,
        user_data: &mut Self,
    ) {
        let unicorn = Engine {
            inner: unsafe { user_data.unicorn.upgrade().unwrap_unchecked() },
        };
        let callback = &mut user_data.callback;
        callback(unicorn, address, size as _)
    }
}

/// Hook basic blocks
impl<'a, D: 'a, CB: 'a> Hook<'a, D, CB>
where
    CB: FnMut(/*unicorn:*/ Engine<'a, D>, /*address:*/ MemAddress, /*size:*/ usize),
{
    unsafe extern "C" fn trampoline_block(
        _uc: *mut ffi::uc_engine,
        address: u64,
        size: u32,
        user_data: &mut Self,
    ) {
        let unicorn = Engine {
            inner: unsafe { user_data.unicorn.upgrade().unwrap_unchecked() },
        };
        let callback = &mut user_data.callback;
        callback(unicorn, address, size as _)
    }
}

/// Hook interupts
impl<'a, D: 'a, CB: 'a> Hook<'a, D, CB>
where
    CB: FnMut(/*unicorn:*/ Engine<'a, D>, /*number:*/ u32),
{
    unsafe extern "C" fn trampoline_intr(
        _uc: *mut ffi::uc_engine,
        number: u32,
        user_data: &mut Self,
    ) {
        let unicorn = Engine {
            inner: unsafe { user_data.unicorn.upgrade().unwrap_unchecked() },
        };
        let callback = &mut user_data.callback;
        callback(unicorn, number)
    }
}

/// Hook invalid instructions and optionally resume execution
impl<'a, D: 'a, CB: 'a> Hook<'a, D, CB>
where
    CB: FnMut(/*unicorn:*/ Engine<'a, D>) -> bool,
{
    unsafe extern "C" fn trampoline_insn_invalid(
        _uc: *mut ffi::uc_engine,
        user_data: &mut Self,
    ) -> bool {
        let unicorn = Engine {
            inner: unsafe { user_data.unicorn.upgrade().unwrap_unchecked() },
        };
        let callback = &mut user_data.callback;
        callback(unicorn)
    }
}

/// Hook X86 SYSCALL instruction
impl<'a, D: 'a, CB: 'a> Hook<'a, D, CB>
where
    CB: FnMut(/*unicorn:*/ Engine<'a, D>),
{
    unsafe extern "C" fn trampoline_insn_syscall(_uc: *mut ffi::uc_engine, user_data: &mut Self) {
        let unicorn = Engine {
            inner: unsafe { user_data.unicorn.upgrade().unwrap_unchecked() },
        };
        let callback = &mut user_data.callback;
        callback(unicorn)
    }
}

/// Hook X86 SYSENTER instruction
impl<'a, D: 'a, CB: 'a> Hook<'a, D, CB>
where
    CB: FnMut(/*unicorn:*/ Engine<'a, D>),
{
    unsafe extern "C" fn trampoline_insn_sysenter(_uc: *mut ffi::uc_engine, user_data: &mut Self) {
        let unicorn = Engine {
            inner: unsafe { user_data.unicorn.upgrade().unwrap_unchecked() },
        };
        let callback = &mut user_data.callback;
        callback(unicorn)
    }
}

/// Hook X86 CPUID instruction
impl<'a, D: 'a, CB: 'a> Hook<'a, D, CB>
where
    CB: FnMut(/*unicorn:*/ Engine<'a, D>),
{
    unsafe extern "C" fn trampoline_insn_cpuid(_uc: *mut ffi::uc_engine, user_data: &mut Self) {
        let unicorn = Engine {
            inner: unsafe { user_data.unicorn.upgrade().unwrap_unchecked() },
        };
        let callback = &mut user_data.callback;
        callback(unicorn)
    }
}

/// Hook X86 IN instruction
impl<'a, D: 'a, CB: 'a> Hook<'a, D, CB>
where
    CB: FnMut(/*unicorn:*/ Engine<'a, D>, /*port:*/ u32, /*size:*/ usize) -> u32,
{
    unsafe extern "C" fn trampoline_insn_in(
        _uc: *mut ffi::uc_engine,
        port: u32,
        size: u32,
        user_data: &mut Self,
    ) -> u32 {
        let unicorn = Engine {
            inner: unsafe { user_data.unicorn.upgrade().unwrap_unchecked() },
        };
        let callback = &mut user_data.callback;
        callback(unicorn, port, size as _)
    }
}

/// Hook X86 OUT instruction
impl<'a, D: 'a, CB: 'a> Hook<'a, D, CB>
where
    CB: FnMut(
        /*unicorn:*/ Engine<'a, D>,
        /*port:*/ u32,
        /*size:*/ usize,
        /*value:*/ u32,
    ),
{
    unsafe extern "C" fn trampoline_insn_out(
        _uc: *mut ffi::uc_engine,
        port: u32,
        size: u32,
        value: u32,
        user_data: &mut Self,
    ) {
        let unicorn = Engine {
            inner: unsafe { user_data.unicorn.upgrade().unwrap_unchecked() },
        };
        let callback = &mut user_data.callback;
        callback(unicorn, port, size as _, value)
    }
}

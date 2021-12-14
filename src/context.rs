use crate::ffi;
use crate::result::{Error, Result};
use crate::Engine;
use std::ptr::null_mut;

/// Storage for CPU context
pub struct Context {
    pub(crate) context: *mut ffi::uc_context,
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            if self.context != null_mut() {
                ffi::uc_context_free(self.context);
                self.context = null_mut();
            }
        }
    }
}

impl Context {
    /// Allocate and return an empty Unicorn context.
    ///
    /// To be populated via save.
    pub fn new_empty<'a, D>(unicorn: &Engine<'a, D>) -> Result<Self> {
        unsafe {
            let mut context = null_mut();
            Error::check(ffi::uc_context_alloc(unicorn.uc(), &mut context))?;
            Ok(Context { context })
        }
    }

    /// Allocate and return a Context struct initialized with the current CPU context.
    ///
    /// This can be used for fast rollbacks with context_restore.
    /// In case of many non-concurrent context saves, use context_alloc and context_save_into
    /// individually to avoid unnecessary allocations.
    /// Save current Unicorn context to previously allocated Context struct.
    pub fn new_saved<'a, D>(unicorn: &Engine<'a, D>) -> Result<Self> {
        let mut context = Self::new_empty(unicorn)?;
        context.save(unicorn)?;
        Ok(context)
    }

    /// Save current Unicorn context to previously allocated Context struct.
    pub fn save<'a, D>(&mut self, unicorn: &Engine<'a, D>) -> Result<()> {
        unsafe { Error::check(ffi::uc_context_save(unicorn.uc(), self.context)) }
    }

    /// Restore a previously saved Unicorn context.
    ///
    /// Perform a quick rollback of the CPU context, including registers and some
    /// internal metadata. Contexts may not be shared across engine instances with
    /// differing arches or modes. Memory has to be restored manually, if needed.
    pub fn restore<'a, D>(&self, unicorn: &mut Engine<'a, D>) -> Result<()> {
        unsafe { Error::check(ffi::uc_context_restore(unicorn.uc(), self.context)) }
    }
}

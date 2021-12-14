use crate::MemAddress;
use crate::engine::Engine;
use crate::result::Result;

impl<'a, D> Engine<'a, D> {
    pub fn stack32_push(&mut self, value: u32) -> Result<MemAddress> {
        let address = self.reg_read().esp() as MemAddress - 4 as MemAddress;
        unsafe {
            let buffer = u32::to_le_bytes(value);
            self.mem_write_raw(address, buffer.as_ptr() as *const _, 4)?;
        }
        self.reg_write().esp(address as _);
        Ok(address as _)
    }

    pub fn stack32_peek(&self, index: usize) -> Result<u32> {
        let address = self.reg_read().esp() as MemAddress + (index * 4) as MemAddress;
        unsafe {
            let mut buffer = [0u8; 4];
            self.mem_read_raw(address, buffer.as_mut_ptr() as *mut _, 4)?;
            Ok(u32::from_le_bytes(buffer))
        }
    }

    pub fn stack32_pop(&mut self) -> Result<u32> {
        let address = self.reg_read().esp() as MemAddress;
        unsafe {
            let mut buffer = [0u8; 4];
            self.mem_read_raw(address, buffer.as_mut_ptr() as *mut _, 4)?;
            let address = address + 4 as MemAddress;
            self.reg_write().esp(address as _);
            Ok(u32::from_le_bytes(buffer))
        }
    }
}

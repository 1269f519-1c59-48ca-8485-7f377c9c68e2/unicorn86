use crate::MemAddress;
use crate::engine::Engine;
use crate::result::Result;

impl<'a, D> Engine<'a, D> {
    pub fn stack32_push_bytes(&mut self, value: &[u8]) -> Result<MemAddress> {
        let rounded_len = ((value.len() + 3) / 4) * 4;
        let address = self.reg_read().esp() as MemAddress - rounded_len as MemAddress;
        self.mem_write(address, value)?;
        self.reg_write().esp(address as _);
        Ok(address as _)
    }

    pub fn stack32_push(&mut self, value: u32) -> Result<MemAddress> {
        let address = self.reg_read().esp() as MemAddress - 4 as MemAddress;
        self.mem_write_u32(address, value)?;
        self.reg_write().esp(address as _);
        Ok(address as _)
    }

    pub fn stack32_peek(&self, index: usize) -> Result<u32> {
        let address = self.reg_read().esp() as MemAddress + (index * 4) as MemAddress;
        self.mem_read_u32(address)
    }

    pub fn stack32_pop(&mut self) -> Result<u32> {
        let address = self.reg_read().esp() as MemAddress;
        let value = self.mem_read_u32(address)?;
        self.reg_write().esp((address + 4) as _);
        Ok(value)
    }

    pub fn stack64_push_bytes(&mut self, value: &[u8]) -> Result<MemAddress> {
        let rounded_len = ((value.len() + 7) / 8) * 8;
        let address = self.reg_read().rsp() as MemAddress - rounded_len as MemAddress;
        self.mem_write(address, value)?;
        self.reg_write().rsp(address as _);
        Ok(address as _)
    }

    pub fn stack64_push(&mut self, value: u64) -> Result<MemAddress> {
        let address = self.reg_read().rsp() as MemAddress - 8 as MemAddress;
        self.mem_write_u64(address, value)?;
        self.reg_write().rsp(address as _);
        Ok(address as _)
    }

    pub fn stack64_peek(&self, index: usize) -> Result<u64> {
        let address = self.reg_read().rsp() as MemAddress + (index * 8) as MemAddress;
        self.mem_read_u64(address)
    }

    pub fn stack64_pop(&mut self) -> Result<u64> {
        let address = self.reg_read().rsp() as MemAddress;
        let value = self.mem_read_u64(address)?;
        self.reg_write().rsp((address  + 8) as _);
        Ok(value)
    }
}

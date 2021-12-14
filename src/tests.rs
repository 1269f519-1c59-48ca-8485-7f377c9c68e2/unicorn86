#![allow(unused)]
#![allow(dead_code)]

use crate::*;
use std::{
    borrow::{Borrow, BorrowMut},
    ops::{Add, AddAssign},
    os::raw::c_void,
    ptr::null_mut,
    rc::Rc,
    sync::Mutex,
};

const CODE_START: u64 = 0x1000;
const CODE_LEN: usize = 0x4000;

fn common_setup(mode: Mode, code: &[u8]) -> Engine<()> {
    let mut uc = Engine::new(CPU::DEFAULT, mode).unwrap();
    uc.mem_map(CODE_START, CODE_LEN, MemProt::ALL).unwrap();
    uc.mem_write(CODE_START, code).unwrap();
    uc
}

#[test]
fn test_x86_in() {
    let code = b"\xe5\x10";
    let mut user_data = (0u32, 0usize);
    {
        let mut uc = common_setup(Mode::X32, code);
        let hook = uc
            .hook_add_insn_in(
                |mut uc, port, size| -> u32 {
                    println!("test {}: {}", port, size);
                    user_data = (port, size);
                    0
                },
                None,
            )
            .unwrap();
        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
            .unwrap();
    }
    assert_eq!(user_data, (0x10, 4));
}

#[test]
fn test_x86_out() {
    let code = b"\xb0\x32\xe6\x46";
    let mut user_data = (0u32, 0usize, 0u32);
    {
        let mut uc = common_setup(Mode::X32, code);
        let hook = uc
            .hook_add_insn_out(
                |mut uc, port, size, value| {
                    user_data = (port, size, value);
                },
                None,
            )
            .unwrap();
        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
            .unwrap();
    }
    assert_eq!(user_data, (0x46, 1, 0x32));
}

#[test]
fn test_mem_hook_all() {
    let code = b"\xb8\xef\xbe\xad\xde\xa3\x00\x80\x00\x00\xa1\x00\x00\x01\x00";
    let mut user_data = <Vec<(MemAccess, u64, usize, u64)>>::new();

    unsafe {
        let mut uc = common_setup(Mode::X32, code);
        uc.mem_map(0x8000, 0x1000, MemProt::ALL).unwrap();
        let hook = uc
            .hook_add_mem(
                |mut uc, access, address, size, value| -> bool {
                    user_data.push((access, address, size, value));
                    if access == MemAccess::READ_UNMAPPED {
                        uc.mem_map(address, 0x1000, MemProt::ALL).unwrap();
                    }
                    true
                },
                MemHook::ALL,
                None,
            )
            .unwrap();
        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
            .unwrap();
    }

    assert_eq!(user_data.len(), 3);
    assert_eq!(user_data[0], (MemAccess::WRITE, 0x8000, 4, 0xdeadbeef));
    assert_eq!(user_data[1], (MemAccess::READ_UNMAPPED, 0x10000, 4, 0));
    assert_eq!(user_data[2], (MemAccess::READ, 0x10000, 4, 0));
}

#[test]
fn test_x86_inc_dec_pxor() {
    let code = b"\x41\x4a\x66\x0f\xef\xc1";
    let mut r_ecx = 0x1234u32;
    let mut r_edx = 0x7890u32;
    let mut r_xmm0 = U128(0x08090a0b0c0d0e0fu64, 0x0001020304050607u64);
    let mut r_xmm1 = U128(0x8090a0b0c0d0e0f0u64, 0x0010203040506070u64);

    unsafe {
        let mut uc = common_setup(Mode::X32, code);
        uc.reg_write().ecx(r_ecx);
        uc.reg_write().edx(r_edx);
        uc.reg_write().xmm0(r_xmm0);
        uc.reg_write().xmm1(r_xmm1);
        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
            .unwrap();
        r_ecx = uc.reg_read().ecx();
        r_edx = uc.reg_read().edx();
        r_xmm0 = uc.reg_read().xmm0();
        r_xmm1 = uc.reg_read().xmm1();
    }

    assert_eq!(r_ecx, 0x1235);
    assert_eq!(r_edx, 0x788f);
    assert_eq!(r_xmm0.0, 0x8899aabbccddeeff);
    assert_eq!(r_xmm0.1, 0x0011223344556677);
}

#[test]
fn test_x86_relative_jump() {
    let code = b"\xeb\x02\x90\x90\x90\x90\x90\x90";
    let mut r_eip = 0u32;

    unsafe {
        let mut uc = common_setup(Mode::X32, code);
        uc.emu_start(CODE_START, CODE_START + 4, 0, 0).unwrap();
        r_eip = uc.reg_read().eip();
    }

    assert_eq!(r_eip, (CODE_START + 4) as u32);
}

#[test]
fn test_x86_loop() {
    let code = b"\x41\x4a\xeb\xfe";
    let mut r_ecx = 0x1234;
    let mut r_edx = 0x7890;

    unsafe {
        let mut uc = common_setup(Mode::X32, code);
        uc.reg_write().ecx(r_ecx);
        uc.reg_write().edx(r_edx);
        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 1000000, 1000)
            .unwrap();
        r_ecx = uc.reg_read().ecx();
        r_edx = uc.reg_read().edx();
    }

    assert_eq!(r_ecx, 0x1235);
    assert_eq!(r_edx, 0x788f);
}

#[test]
fn test_x86_invalid_mem_read() {
    let code = b"\x8b\x0d\xaa\xaa\xaa\xaa";
    {
        let mut uc = common_setup(Mode::X32, code);
        let err = uc
            .emu_start(CODE_START, CODE_START + code.len() as u64, 1000000, 1000)
            .unwrap_err();
        assert_eq!(err, Error::ReadUnmapped);
    }
}

#[test]
fn test_x86_invalid_mem_write() {
    let code = b"\x89\x0d\xaa\xaa\xaa\xaa";
    {
        let mut uc = common_setup(Mode::X32, code);
        let err = uc
            .emu_start(CODE_START, CODE_START + code.len() as u64, 1000000, 1000)
            .unwrap_err();
        assert_eq!(err, Error::WriteUnmapped);
    }
}

#[test]
fn test_x86_invalid_jump() {
    let code = b"\xe9\xe9\xee\xee\xee";
    {
        let mut uc = common_setup(Mode::X32, code);
        let err = uc
            .emu_start(CODE_START, CODE_START + code.len() as u64, 1000000, 1000)
            .unwrap_err();
        assert_eq!(err, Error::FetchUnmapped);
    }
}

#[test]
fn test_x86_missing_code() {
    let mut r_ecx = 0x1234;
    let mut r_edx = 0x7890;
    unsafe {
        let mut uc = Engine::new(CPU::DEFAULT, Mode::X32).unwrap();
        uc.reg_write().ecx(r_ecx);
        uc.reg_write().edx(r_edx);
        let hook = uc
            .hook_add_mem(
                |mut uc, access, address, size, value| -> bool {
                    let code = b"\x41\x4a";
                    let aligned_address = address & !0xFFFu64;
                    let aligned_size = ((size as usize / 0x1000) + 1) * 0x1000;

                    uc.mem_map(aligned_address, aligned_size, MemProt::ALL)
                        .unwrap();
                    uc.mem_write(aligned_address, code).unwrap();
                    true
                },
                MemHook::UNMAPPED,
                None,
            )
            .unwrap();
        uc.emu_start(CODE_START, CODE_START + 2, 0, 0).unwrap();
        r_ecx = uc.reg_read().ecx();
        r_edx = uc.reg_read().edx();
    }
    assert_eq!(r_ecx, 0x1235);
    assert_eq!(r_edx, 0x788f);
}

#[test]
fn test_x86_64_syscall() {
    let code = b"\x0f\x05";
    let r_rax = 0x100u32;
    unsafe {
        let mut uc = common_setup(Mode::X64, code);
        uc.reg_write().eax(r_rax);
        let hook = uc
            .hook_add_insn_syscall(
                |unciron| {
                    let r_rax = unciron.reg_read().eax();
                    assert_eq!(r_rax, 0x100u32);
                },
                None,
            )
            .unwrap();
        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 1000000, 1000)
            .unwrap();
    }
}

#[test]
fn test_x86_sysenter() {
    let code = b"\x0F\x34";
    let mut called = false;
    unsafe {
        let mut uc = common_setup(Mode::X32, code);
        let hook = uc
            .hook_add_insn_sysenter(
                |unciron| {
                    called = true;
                },
                None,
            )
            .unwrap();
        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 1000000, 1000)
            .unwrap();
    }
    assert_eq!(called, true);
}

#[test]
fn test_x86_hook_cpuid() {
    let code = b"\x40\x0F\xA2";
    let mut r_eax = 0u32;
    unsafe {
        let mut uc = common_setup(Mode::X32, code);
        let hook = uc
            .hook_add_insn_cpuid(
                |mut unciron| {
                    unciron.reg_write().eax(7);
                },
                None,
            )
            .unwrap();
        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 1000000, 1000)
            .unwrap();
        r_eax = uc.reg_read().eax();
    }
    assert_eq!(r_eax, 7);
}

#[test]
fn test_x86_16_add() {
    let code = b"\x00\x00";
    let r_eax = 7u32;
    let r_ebx = 5u32;
    let r_esi = 6u32;
    let mut result = [0u8];
    unsafe {
        let mut uc = common_setup(Mode::X16, code);
        uc.mem_map(0, 0x1000, MemProt::ALL).unwrap();
        uc.reg_write().eax(r_eax);
        uc.reg_write().ebx(r_ebx);
        uc.reg_write().esi(r_esi);
        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
            .unwrap();
        uc.mem_read((r_ebx + r_esi) as u64, &mut result).unwrap();
    }
    assert_eq!(result[0], 7u8);
}

#[test]
fn test_x86_reg_save() {
    let code = b"\x40";
    let mut r_eax = 1u32;
    unsafe {
        let mut uc = common_setup(Mode::X32, code);
        uc.reg_write().eax(r_eax);
        let ctx = Context::new_saved(&uc).unwrap();
        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
            .unwrap();
        ctx.restore(&mut uc).unwrap();
        r_eax = uc.reg_read().eax();
    }
    assert_eq!(r_eax, 1);
}

#[test]
fn test_x86_invalid_mem_read_stop_in_cb() {
    let code = b"\x40\x8b\x1d\x00\x00\x10\x00\x42";
    let mut r_eax = 0x1234u32;
    let mut r_edx = 0x5678u32;
    let mut r_eip = 0u32;
    {
        let mut uc = common_setup(Mode::X32, code);
        let hook = uc
            .hook_add_mem(
                |unciorn, access, address, size, value| false,
                MemHook::ALL,
                None,
            )
            .unwrap();
        uc.reg_write().eax(r_eax);
        uc.reg_write().edx(r_edx);
        let err = uc
            .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
            .unwrap_err();
        r_eax = uc.reg_read().eax();
        r_edx = uc.reg_read().edx();
        r_eip = uc.reg_read().eip();
        assert_eq!(err, Error::ReadUnmapped);
    }
    assert_eq!(r_eip, (CODE_START + 1) as u32);
    assert_eq!(r_eax, 0x1235u32);
    assert_eq!(r_edx, 0x5678u32);
}

#[test]
fn test_x86_smc_xor() {
    let code = b"\x31\x47\x03\x13\x8b\xa9\x3e";
    let mut r_edi = CODE_START as u32;
    let mut r_eax = 0xbc4177e6u32;
    let mut result = [0u32];

    unsafe {
        let mut uc = common_setup(Mode::X32, code);
        uc.reg_write().edi(r_edi);
        uc.reg_write().eax(r_eax);
        uc.emu_start(CODE_START, CODE_START + 3, 0, 0).unwrap();
        uc.mem_read_raw(CODE_START + 3, &mut result as *mut _ as *mut _, 4)
            .unwrap();
    }
    assert_eq!(result[0], 0x3ea98b13 ^ 0xbc4177e6);
}

#[test]
fn test_x86_x87_fnstenv() {
    let code = b"\xd9\xd0\xd9\x30\xd9\x00\xd9\x30";
    let base = CODE_START + 3 * CODE_LEN as u64;
    type UD = [u32; 1];
    let mut user_data = [0u32; 1];
    let mut fnstenv = [0u32; 7];
    unsafe {
        let mut uc = common_setup(Mode::X32, code);
        uc.mem_map(base, CODE_LEN, MemProt::ALL).unwrap();
        uc.reg_write().eax(base as u32);
        let hook = uc
            .hook_add_code(
                |mut uc, address, size| {
                    if address == CODE_START + 4 {
                        user_data[0] = uc.reg_read().eip();
                        let r_eax = uc.reg_read().eax();
                        let mut fnstenv = [0u32; 7];
                        uc.mem_read_raw(base, &mut fnstenv as *mut _ as _, 4 * 7)
                            .unwrap();
                        assert_eq!(fnstenv[3], 0);
                    }
                },
                None,
            )
            .unwrap();
        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
            .unwrap();
        uc.mem_read_raw(base, &mut fnstenv as *mut _ as _, 4 * 7)
            .unwrap();
    }
    assert_eq!(fnstenv[3], user_data[0]);
}

/*
#[test]
fn test_x86_mmio() {
    let code = b"\x89\x0d\x04\x00\x02\x00\x8b\x0d\x04\x00\x02\x00";
    let mut r_ecx = 0xdeadbeefu32;

    unsafe {
        let mut uc = common_setup(UcModeX86::X32, code);
        uc.reg_write(uc_x86_reg::ECX, r_ecx).unwrap();
        uc.mmio_map(
            0x20000,
            0x1000,
            callback_read,
            &mut (),
            callback_write,
            &mut (),
        )
        .unwrap();

        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
            .unwrap();

        r_ecx = uc.reg_read(uc_x86_reg::ECX).unwrap();

        uc.close().unwrap();
    }
    assert_eq!(r_ecx, 0x19260817);

    unsafe extern "C" fn callback_read(_uc: UcEngine, offset: u64, size: u32, _ud: *mut ()) -> u64 {
        assert_eq!(offset, 4);
        assert_eq!(size, 4);

        return 0x19260817;
    }

    unsafe extern "C" fn callback_write(
        _uc: UcEngine,
        offset: u64,
        size: u32,
        value: u64,
        _ud: *mut (),
    ) {
        assert_eq!(offset, 4);
        assert_eq!(size, 4);
        assert_eq!(value, 0xdeadbeef);
    }
}

#[test]
fn test_x86_mmio_uc_mem_rw() {
    let mut data = [0xdeadbeefu32];

    unsafe {
        let mut uc = UcEngine::open_x86(UcModeX86::X32).unwrap();

        uc.mmio_map(
            0x20000,
            0x1000,
            callback_read,
            &mut (),
            callback_write,
            &mut (),
        )
        .unwrap();

        uc.mem_write(0x20004, &data).unwrap();
        uc.mem_read(0x20008, &mut data).unwrap();

        uc.close().unwrap();
    }
    assert_eq!(data[0], 0x19260817);

    unsafe extern "C" fn callback_read(_uc: UcEngine, offset: u64, size: u32, _ud: *mut ()) -> u64 {
        assert_eq!(offset, 8);
        assert_eq!(size, 4);

        return 0x19260817;
    }

    unsafe extern "C" fn callback_write(
        _uc: UcEngine,
        offset: u64,
        size: u32,
        value: u64,
        _ud: *mut (),
    ) {
        assert_eq!(offset, 4);
        assert_eq!(size, 4);
        assert_eq!(value, 0xdeadbeef);
    }
}
*/

fn hook_inside_a_hook() {
    let mut uc = Engine::new(CPU::DEFAULT, Mode::X32).unwrap();
    {
        {
            uc.hook_add_intr(
                |mut uc, number| {
                    Some(uc.hook_add_intr(|mut uc, number| {}, None).unwrap());
                },
                None,
            )
            .unwrap();
        }
    }
}

pub struct Wrapped<'a> {
    unicorn: Engine<'a, ()>,
    stuff: Rc<Mutex<u32>>,
}

impl Wrapped<'_> {
    pub fn new() -> Self {
        let code = b"\xe5\x10";
        let mut result = Self {
            unicorn: common_setup(Mode::X32, code),
            stuff: Rc::new(Mutex::new(12)),
        };
        let stuff = result.stuff.clone();
        result
            .unicorn
            .hook_add_insn_in(
                move |mut uc, port, size| -> u32 {
                    println!("test {}: {}", port, size);
                    stuff.lock().unwrap().borrow_mut().add_assign(10);
                    0
                },
                None,
            )
            .unwrap();
        result
    }

    pub fn run(&mut self) {
        self.unicorn
            .emu_start(CODE_START, CODE_START + 2 as u64, 0, 0)
            .unwrap();
    }

    pub fn result(&self) -> u32 {
        self.stuff.lock().unwrap().clone()
    }
}

#[test]
fn test_wrapped() {
    let mut wrapped = Wrapped::new();
    wrapped.run();
    let result = wrapped.result();
    assert_eq!(result, 22)
}

#[test]
fn test_stack() {
    let mut uc = Engine::new(CPU::DEFAULT, Mode::X32).unwrap();
    let stack_start = 0x4000;
    let stack_end = stack_start + 0x1000;
    uc.mem_map(stack_start, 0x1000, MemProt::ALL).unwrap();
    uc.reg_write().esp(stack_end as _);


    let push_esp = uc.stack32_push(1337).unwrap();
    let result = uc.stack32_pop().unwrap();

    assert_eq!(result, 1337);
    assert_eq!(push_esp, stack_end - 4);
}

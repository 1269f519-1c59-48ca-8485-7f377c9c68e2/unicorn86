use crate::engine::Engine;
use crate::ffi;
use crate::result::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug, Hash)]
#[repr(C)]
pub struct MSR {
    pub rid: u32,
    pub value: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug, Hash)]
#[repr(C)]
pub struct MMR {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug, Hash)]
#[repr(C)]
pub struct F80(/*mantisa:*/ pub u64, /*exponent:*/ pub u16);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug, Hash)]
#[repr(C)]
pub struct U128(/*lo:*/ pub u64, /*hi:*/ pub u64);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug, Hash)]
#[repr(C)]
pub struct U256(/*lo:*/ pub U128, /*hi:*/ pub U128);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug, Hash)]
#[repr(C)]
pub struct U512(/*lo:*/ pub U256, /*hi:*/ pub U256);

pub struct RegRead<'a, 'b, D>(&'b crate::engine::Engine<'a, D>);

pub struct RegWrite<'a, 'b, D>(&'b mut crate::engine::Engine<'a, D>);

impl<'a, D> Engine<'a, D> {
    /// Reads raw register value
    pub unsafe fn reg_read_raw<T: Copy + Default>(&self, regid: u32) -> T {
        let mut value: T = Default::default();
        ffi::uc_reg_read(
            self.uc(),
            regid as _,
            &mut value as *mut _ as _,
        );
        value
    }

    /// Writes a raw register value
    pub unsafe fn reg_write_raw<T: Copy + Default>(&mut self, regid: u32, value: &T) {
        ffi::uc_reg_write(
            self.uc(),
            regid as _,
            value as *const _ as _,
        );
    }

    /// Read architecture specific register
    pub fn reg_read(&self) -> RegRead<'a, '_, D> {
        RegRead(self)
    }

    /// Write architecture specific register
    pub fn reg_write(&mut self) -> RegWrite<'a, '_, D> {
        RegWrite(self)
    }
}

macro_rules! impl_regs {
    { $($reg_name:ident : $type_name:ty = $original_name:ident)+ } => {
        impl<'a, 'b, D> RegRead<'a, 'b, D> {
            $(
                pub fn $reg_name (self) -> $type_name {
                    unsafe { self.0.reg_read_raw(ffi::$original_name as _) }
                }
            )+
        }

        impl<'a, 'b, D> RegWrite<'a, 'b, D> {
            $(
                pub fn $reg_name (self, value: $type_name) {
                    unsafe { self.0.reg_write_raw(ffi::$original_name as _, &value) }
                }
            )+
        }
    }
}

impl_regs! {
    al: u8 = UC_X86_REG_AL
    ah: u8 = UC_X86_REG_AH
    bl: u8 = UC_X86_REG_BL
    bh: u8 = UC_X86_REG_BH
    cl: u8 = UC_X86_REG_CL
    ch: u8 = UC_X86_REG_CH
    dl: u8 = UC_X86_REG_DL
    dh: u8 = UC_X86_REG_DH
    dil: u8 = UC_X86_REG_DIL
    sil: u8 = UC_X86_REG_SIL
    bpl: u8 = UC_X86_REG_BPL
    spl: u8 = UC_X86_REG_SPL
    r8b: u8 = UC_X86_REG_R8B
    r9b: u8 = UC_X86_REG_R9B
    r10b: u8 = UC_X86_REG_R10B
    r11b: u8 = UC_X86_REG_R11B
    r12b: u8 = UC_X86_REG_R12B
    r13b: u8 = UC_X86_REG_R13B
    r14b: u8 = UC_X86_REG_R14B
    r15b: u8 = UC_X86_REG_R15B

    ax: u16 = UC_X86_REG_AX
    bx: u16 = UC_X86_REG_BX
    cx: u16 = UC_X86_REG_CX
    dx: u16 = UC_X86_REG_DX
    di: u16 = UC_X86_REG_DI
    si: u16 = UC_X86_REG_SI
    bp: u16 = UC_X86_REG_BP
    sp: u16 = UC_X86_REG_SP
    ip: u16 = UC_X86_REG_IP
    cs: u16 = UC_X86_REG_CS
    ds: u16 = UC_X86_REG_DS
    es: u16 = UC_X86_REG_ES
    ss: u16 = UC_X86_REG_SS
    fs: u16 = UC_X86_REG_FS
    gs: u16 = UC_X86_REG_GS
    flags: u16 = UC_X86_REG_FLAGS
    r8w: u16 = UC_X86_REG_R8W
    r9w: u16 = UC_X86_REG_R9W
    r10w: u16 = UC_X86_REG_R10W
    r11w: u16 = UC_X86_REG_R11W
    r12w: u16 = UC_X86_REG_R12W
    r13w: u16 = UC_X86_REG_R13W
    r14w: u16 = UC_X86_REG_R14W
    r15w: u16 = UC_X86_REG_R15W

    eax: u32 = UC_X86_REG_EAX
    ebx: u32 = UC_X86_REG_EBX
    ecx: u32 = UC_X86_REG_ECX
    edx: u32 = UC_X86_REG_EDX
    edi: u32 = UC_X86_REG_EDI
    esi: u32 = UC_X86_REG_ESI
    ebp: u32 = UC_X86_REG_EBP
    esp: u32 = UC_X86_REG_ESP
    eip: u32 = UC_X86_REG_EIP
    eflags: u32 = UC_X86_REG_EFLAGS
    cr0: u32 = UC_X86_REG_CR0
    cr1: u32 = UC_X86_REG_CR1
    cr2: u32 = UC_X86_REG_CR2
    cr3: u32 = UC_X86_REG_CR3
    cr4: u32 = UC_X86_REG_CR4
    cr8: u32 = UC_X86_REG_CR8
    dr0: u32 = UC_X86_REG_DR0
    dr1: u32 = UC_X86_REG_DR1
    dr2: u32 = UC_X86_REG_DR2
    dr3: u32 = UC_X86_REG_DR3
    dr4: u32 = UC_X86_REG_DR4
    dr5: u32 = UC_X86_REG_DR5
    dr6: u32 = UC_X86_REG_DR6
    dr7: u32 = UC_X86_REG_DR7
    r8d: u32 = UC_X86_REG_R8D
    r9d: u32 = UC_X86_REG_R9D
    r10d: u32 = UC_X86_REG_R10D
    r11d: u32 = UC_X86_REG_R11D
    r12d: u32 = UC_X86_REG_R12D
    r13d: u32 = UC_X86_REG_R13D
    r14d: u32 = UC_X86_REG_R14D
    r15d: u32 = UC_X86_REG_R15D

    rax: u64 = UC_X86_REG_RAX
    rbx: u64 = UC_X86_REG_RBX
    rcx: u64 = UC_X86_REG_RCX
    rdx: u64 = UC_X86_REG_RDX
    rdi: u64 = UC_X86_REG_RDI
    rsi: u64 = UC_X86_REG_RSI
    rbp: u64 = UC_X86_REG_RBP
    rsp: u64 = UC_X86_REG_RSP
    rip: u64 = UC_X86_REG_RIP
    rflags: u64 = UC_X86_REG_RFLAGS
    r8: u64 = UC_X86_REG_R8
    r9: u64 = UC_X86_REG_R9
    r10: u64 = UC_X86_REG_R10
    r11: u64 = UC_X86_REG_R11
    r12: u64 = UC_X86_REG_R12
    r13: u64 = UC_X86_REG_R13
    r14: u64 = UC_X86_REG_R14
    r15: u64 = UC_X86_REG_R15

    fp0: F80 = UC_X86_REG_FP0
    fp1: F80 = UC_X86_REG_FP1
    fp2: F80 = UC_X86_REG_FP2
    fp3: F80 = UC_X86_REG_FP3
    fp4: F80 = UC_X86_REG_FP4
    fp5: F80 = UC_X86_REG_FP5
    fp6: F80 = UC_X86_REG_FP6
    fp7: F80 = UC_X86_REG_FP7
    st0: F80 = UC_X86_REG_ST0
    st1: F80 = UC_X86_REG_ST1
    st2: F80 = UC_X86_REG_ST2
    st3: F80 = UC_X86_REG_ST3
    st4: F80 = UC_X86_REG_ST4
    st5: F80 = UC_X86_REG_ST5
    st6: F80 = UC_X86_REG_ST6
    st7: F80 = UC_X86_REG_ST7

    xmm0: U128 = UC_X86_REG_XMM0
    xmm1: U128 = UC_X86_REG_XMM1
    xmm2: U128 = UC_X86_REG_XMM2
    xmm3: U128 = UC_X86_REG_XMM3
    xmm4: U128 = UC_X86_REG_XMM4
    xmm5: U128 = UC_X86_REG_XMM5
    xmm6: U128 = UC_X86_REG_XMM6
    xmm7: U128 = UC_X86_REG_XMM7
    xmm8: U128 = UC_X86_REG_XMM8
    xmm9: U128 = UC_X86_REG_XMM9
    xmm10: U128 = UC_X86_REG_XMM10
    xmm11: U128 = UC_X86_REG_XMM11
    xmm12: U128 = UC_X86_REG_XMM12
    xmm13: U128 = UC_X86_REG_XMM13
    xmm14: U128 = UC_X86_REG_XMM14
    xmm15: U128 = UC_X86_REG_XMM15
    xmm16: U128 = UC_X86_REG_XMM16
    xmm17: U128 = UC_X86_REG_XMM17
    xmm18: U128 = UC_X86_REG_XMM18
    xmm19: U128 = UC_X86_REG_XMM19
    xmm20: U128 = UC_X86_REG_XMM20
    xmm21: U128 = UC_X86_REG_XMM21
    xmm22: U128 = UC_X86_REG_XMM22
    xmm23: U128 = UC_X86_REG_XMM23
    xmm24: U128 = UC_X86_REG_XMM24
    xmm25: U128 = UC_X86_REG_XMM25
    xmm26: U128 = UC_X86_REG_XMM26
    xmm27: U128 = UC_X86_REG_XMM27
    xmm28: U128 = UC_X86_REG_XMM28
    xmm29: U128 = UC_X86_REG_XMM29
    xmm30: U128 = UC_X86_REG_XMM30
    xmm31: U128 = UC_X86_REG_XMM31

    ymm0: U256 = UC_X86_REG_YMM0
    ymm1: U256 = UC_X86_REG_YMM1
    ymm2: U256 = UC_X86_REG_YMM2
    ymm3: U256 = UC_X86_REG_YMM3
    ymm4: U256 = UC_X86_REG_YMM4
    ymm5: U256 = UC_X86_REG_YMM5
    ymm6: U256 = UC_X86_REG_YMM6
    ymm7: U256 = UC_X86_REG_YMM7
    ymm8: U256 = UC_X86_REG_YMM8
    ymm9: U256 = UC_X86_REG_YMM9
    ymm10: U256 = UC_X86_REG_YMM10
    ymm11: U256 = UC_X86_REG_YMM11
    ymm12: U256 = UC_X86_REG_YMM12
    ymm13: U256 = UC_X86_REG_YMM13
    ymm14: U256 = UC_X86_REG_YMM14
    ymm15: U256 = UC_X86_REG_YMM15
    ymm16: U256 = UC_X86_REG_YMM16
    ymm17: U256 = UC_X86_REG_YMM17
    ymm18: U256 = UC_X86_REG_YMM18
    ymm19: U256 = UC_X86_REG_YMM19
    ymm20: U256 = UC_X86_REG_YMM20
    ymm21: U256 = UC_X86_REG_YMM21
    ymm22: U256 = UC_X86_REG_YMM22
    ymm23: U256 = UC_X86_REG_YMM23
    ymm24: U256 = UC_X86_REG_YMM24
    ymm25: U256 = UC_X86_REG_YMM25
    ymm26: U256 = UC_X86_REG_YMM26
    ymm27: U256 = UC_X86_REG_YMM27
    ymm28: U256 = UC_X86_REG_YMM28
    ymm29: U256 = UC_X86_REG_YMM29
    ymm30: U256 = UC_X86_REG_YMM30
    ymm31: U256 = UC_X86_REG_YMM31

    zmm0: U512 = UC_X86_REG_ZMM0
    zmm1: U512 = UC_X86_REG_ZMM1
    zmm2: U512 = UC_X86_REG_ZMM2
    zmm3: U512 = UC_X86_REG_ZMM3
    zmm4: U512 = UC_X86_REG_ZMM4
    zmm5: U512 = UC_X86_REG_ZMM5
    zmm6: U512 = UC_X86_REG_ZMM6
    zmm7: U512 = UC_X86_REG_ZMM7
    zmm8: U512 = UC_X86_REG_ZMM8
    zmm9: U512 = UC_X86_REG_ZMM9
    zmm10: U512 = UC_X86_REG_ZMM10
    zmm11: U512 = UC_X86_REG_ZMM11
    zmm12: U512 = UC_X86_REG_ZMM12
    zmm13: U512 = UC_X86_REG_ZMM13
    zmm14: U512 = UC_X86_REG_ZMM14
    zmm15: U512 = UC_X86_REG_ZMM15
    zmm16: U512 = UC_X86_REG_ZMM16
    zmm17: U512 = UC_X86_REG_ZMM17
    zmm18: U512 = UC_X86_REG_ZMM18
    zmm19: U512 = UC_X86_REG_ZMM19
    zmm20: U512 = UC_X86_REG_ZMM20
    zmm21: U512 = UC_X86_REG_ZMM21
    zmm22: U512 = UC_X86_REG_ZMM22
    zmm23: U512 = UC_X86_REG_ZMM23
    zmm24: U512 = UC_X86_REG_ZMM24
    zmm25: U512 = UC_X86_REG_ZMM25
    zmm26: U512 = UC_X86_REG_ZMM26
    zmm27: U512 = UC_X86_REG_ZMM27
    zmm28: U512 = UC_X86_REG_ZMM28
    zmm29: U512 = UC_X86_REG_ZMM29
    zmm30: U512 = UC_X86_REG_ZMM30
    zmm31: U512 = UC_X86_REG_ZMM31

    fpsw: u16 = UC_X86_REG_FPSW
    fpcw: u16 = UC_X86_REG_FPCW
    fptag: u16 = UC_X86_REG_FPTAG

    mxcsr: u32 = UC_X86_REG_MXCSR

    msr: MSR = UC_X86_REG_MSR

    idtr: MMR = UC_X86_REG_IDTR
    gdtr: MMR = UC_X86_REG_GDTR
    ldtr: MMR = UC_X86_REG_LDTR
    tr: MMR = UC_X86_REG_TR
}

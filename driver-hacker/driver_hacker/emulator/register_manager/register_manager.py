from typing import cast, final

import unicorn  # type: ignore[import-untyped]

from driver_hacker.emulator.register_manager.floating_point_register_wrapper import FloatingPointRegisterWrapper
from driver_hacker.emulator.register_manager.global_memory_management_register_wrapper import (
    GlobalMemoryManagementRegisterWrapper,
)
from driver_hacker.emulator.register_manager.local_memory_management_register_wrapper import (
    LocalMemoryManagementRegisterWrapper,
)


@final
class RegisterManager:
    __uc: unicorn.Uc

    def __init__(self, uc: unicorn.Uc) -> None:
        self.__uc = uc

    @property
    def ah(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_AH))

    @ah.setter
    def ah(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_AH, value)

    @property
    def al(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_AL))

    @al.setter
    def al(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_AL, value)

    @property
    def ax(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_AX))

    @ax.setter
    def ax(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_AX, value)

    @property
    def bh(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_BH))

    @bh.setter
    def bh(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_BH, value)

    @property
    def bl(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_BL))

    @bl.setter
    def bl(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_BL, value)

    @property
    def bp(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_BP))

    @bp.setter
    def bp(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_BP, value)

    @property
    def bpl(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_BPL))

    @bpl.setter
    def bpl(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_BPL, value)

    @property
    def bx(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_BX))

    @bx.setter
    def bx(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_BX, value)

    @property
    def ch(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_CH))

    @ch.setter
    def ch(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_CH, value)

    @property
    def cl(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_CL))

    @cl.setter
    def cl(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_CL, value)

    @property
    def cs(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_CS))

    @cs.setter
    def cs(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_CS, value)

    @property
    def cx(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_CX))

    @cx.setter
    def cx(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_CX, value)

    @property
    def dh(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DH))

    @dh.setter
    def dh(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DH, value)

    @property
    def di(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DI))

    @di.setter
    def di(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DI, value)

    @property
    def dil(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DIL))

    @dil.setter
    def dil(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DIL, value)

    @property
    def dl(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DL))

    @dl.setter
    def dl(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DL, value)

    @property
    def ds(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DS))

    @ds.setter
    def ds(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DS, value)

    @property
    def dx(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DX))

    @dx.setter
    def dx(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DX, value)

    @property
    def eax(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_EAX))

    @eax.setter
    def eax(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_EAX, value)

    @property
    def ebp(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_EBP))

    @ebp.setter
    def ebp(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_EBP, value)

    @property
    def ebx(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_EBX))

    @ebx.setter
    def ebx(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_EBX, value)

    @property
    def ecx(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ECX))

    @ecx.setter
    def ecx(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ECX, value)

    @property
    def edi(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_EDI))

    @edi.setter
    def edi(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_EDI, value)

    @property
    def edx(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_EDX))

    @edx.setter
    def edx(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_EDX, value)

    @property
    def eflags(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_EFLAGS))

    @eflags.setter
    def eflags(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_EFLAGS, value)

    @property
    def eip(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_EIP))

    @eip.setter
    def eip(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_EIP, value)

    @property
    def es(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ES))

    @es.setter
    def es(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ES, value)

    @property
    def esi(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ESI))

    @esi.setter
    def esi(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ESI, value)

    @property
    def esp(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP))

    @esp.setter
    def esp(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ESP, value)

    @property
    def fpsw(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_FPSW))

    @fpsw.setter
    def fpsw(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FPSW, value)

    @property
    def fs(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_FS))

    @fs.setter
    def fs(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FS, value)

    @property
    def gs(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_GS))

    @gs.setter
    def gs(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_GS, value)

    @property
    def ip(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_IP))

    @ip.setter
    def ip(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_IP, value)

    @property
    def rax(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_RAX))

    @rax.setter
    def rax(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_RAX, value)

    @property
    def rbp(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_RBP))

    @rbp.setter
    def rbp(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_RBP, value)

    @property
    def rbx(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_RBX))

    @rbx.setter
    def rbx(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_RBX, value)

    @property
    def rcx(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_RCX))

    @rcx.setter
    def rcx(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_RCX, value)

    @property
    def rdi(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_RDI))

    @rdi.setter
    def rdi(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_RDI, value)

    @property
    def rdx(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_RDX))

    @rdx.setter
    def rdx(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_RDX, value)

    @property
    def rip(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP))

    @rip.setter
    def rip(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_RIP, value)

    @property
    def rsi(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_RSI))

    @rsi.setter
    def rsi(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_RSI, value)

    @property
    def rsp(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_RSP))

    @rsp.setter
    def rsp(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_RSP, value)

    @property
    def si(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_SI))

    @si.setter
    def si(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_SI, value)

    @property
    def sil(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_SIL))

    @sil.setter
    def sil(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_SIL, value)

    @property
    def sp(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_SP))

    @sp.setter
    def sp(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_SP, value)

    @property
    def spl(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_SPL))

    @spl.setter
    def spl(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_SPL, value)

    @property
    def ss(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_SS))

    @ss.setter
    def ss(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_SS, value)

    @property
    def cr0(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_CR0))

    @cr0.setter
    def cr0(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_CR0, value)

    @property
    def cr1(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_CR1))

    @cr1.setter
    def cr1(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_CR1, value)

    @property
    def cr2(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_CR2))

    @cr2.setter
    def cr2(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_CR2, value)

    @property
    def cr3(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_CR3))

    @cr3.setter
    def cr3(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_CR3, value)

    @property
    def cr4(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_CR4))

    @cr4.setter
    def cr4(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_CR4, value)

    @property
    def cr8(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_CR8))

    @cr8.setter
    def cr8(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_CR8, value)

    @property
    def dr0(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DR0))

    @dr0.setter
    def dr0(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DR0, value)

    @property
    def dr1(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DR1))

    @dr1.setter
    def dr1(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DR1, value)

    @property
    def dr2(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DR2))

    @dr2.setter
    def dr2(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DR2, value)

    @property
    def dr3(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DR3))

    @dr3.setter
    def dr3(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DR3, value)

    @property
    def dr4(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DR4))

    @dr4.setter
    def dr4(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DR4, value)

    @property
    def dr5(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DR5))

    @dr5.setter
    def dr5(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DR5, value)

    @property
    def dr6(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DR6))

    @dr6.setter
    def dr6(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DR6, value)

    @property
    def dr7(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_DR7))

    @dr7.setter
    def dr7(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_DR7, value)

    @property
    def fp0(self) -> FloatingPointRegisterWrapper:
        return FloatingPointRegisterWrapper(self.__uc, unicorn.x86_const.UC_X86_REG_FP0)

    @fp0.setter
    def fp0(self, value: tuple[int, int]) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FP0, value)

    @property
    def fp1(self) -> FloatingPointRegisterWrapper:
        return FloatingPointRegisterWrapper(self.__uc, unicorn.x86_const.UC_X86_REG_FP1)

    @fp1.setter
    def fp1(self, value: tuple[int, int]) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FP1, value)

    @property
    def fp2(self) -> FloatingPointRegisterWrapper:
        return FloatingPointRegisterWrapper(self.__uc, unicorn.x86_const.UC_X86_REG_FP2)

    @fp2.setter
    def fp2(self, value: tuple[int, int]) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FP2, value)

    @property
    def fp3(self) -> FloatingPointRegisterWrapper:
        return FloatingPointRegisterWrapper(self.__uc, unicorn.x86_const.UC_X86_REG_FP3)

    @fp3.setter
    def fp3(self, value: tuple[int, int]) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FP3, value)

    @property
    def fp4(self) -> FloatingPointRegisterWrapper:
        return FloatingPointRegisterWrapper(self.__uc, unicorn.x86_const.UC_X86_REG_FP4)

    @fp4.setter
    def fp4(self, value: tuple[int, int]) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FP4, value)

    @property
    def fp5(self) -> FloatingPointRegisterWrapper:
        return FloatingPointRegisterWrapper(self.__uc, unicorn.x86_const.UC_X86_REG_FP5)

    @fp5.setter
    def fp5(self, value: tuple[int, int]) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FP5, value)

    @property
    def fp6(self) -> FloatingPointRegisterWrapper:
        return FloatingPointRegisterWrapper(self.__uc, unicorn.x86_const.UC_X86_REG_FP6)

    @fp6.setter
    def fp6(self, value: tuple[int, int]) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FP6, value)

    @property
    def fp7(self) -> FloatingPointRegisterWrapper:
        return FloatingPointRegisterWrapper(self.__uc, unicorn.x86_const.UC_X86_REG_FP7)

    @fp7.setter
    def fp7(self, value: tuple[int, int]) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FP7, value)

    @property
    def k0(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_K0))

    @k0.setter
    def k0(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_K0, value)

    @property
    def k1(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_K1))

    @k1.setter
    def k1(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_K1, value)

    @property
    def k2(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_K2))

    @k2.setter
    def k2(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_K2, value)

    @property
    def k3(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_K3))

    @k3.setter
    def k3(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_K3, value)

    @property
    def k4(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_K4))

    @k4.setter
    def k4(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_K4, value)

    @property
    def k5(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_K5))

    @k5.setter
    def k5(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_K5, value)

    @property
    def k6(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_K6))

    @k6.setter
    def k6(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_K6, value)

    @property
    def k7(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_K7))

    @k7.setter
    def k7(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_K7, value)

    @property
    def mm0(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_MM0))

    @mm0.setter
    def mm0(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_MM0, value)

    @property
    def mm1(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_MM1))

    @mm1.setter
    def mm1(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_MM1, value)

    @property
    def mm2(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_MM2))

    @mm2.setter
    def mm2(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_MM2, value)

    @property
    def mm3(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_MM3))

    @mm3.setter
    def mm3(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_MM3, value)

    @property
    def mm4(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_MM4))

    @mm4.setter
    def mm4(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_MM4, value)

    @property
    def mm5(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_MM5))

    @mm5.setter
    def mm5(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_MM5, value)

    @property
    def mm6(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_MM6))

    @mm6.setter
    def mm6(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_MM6, value)

    @property
    def mm7(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_MM7))

    @mm7.setter
    def mm7(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_MM7, value)

    @property
    def r8(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R8))

    @r8.setter
    def r8(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R8, value)

    @property
    def r9(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R9))

    @r9.setter
    def r9(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R9, value)

    @property
    def r10(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R10))

    @r10.setter
    def r10(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R10, value)

    @property
    def r11(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R11))

    @r11.setter
    def r11(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R11, value)

    @property
    def r12(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R12))

    @r12.setter
    def r12(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R12, value)

    @property
    def r13(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R13))

    @r13.setter
    def r13(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R13, value)

    @property
    def r14(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R14))

    @r14.setter
    def r14(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R14, value)

    @property
    def r15(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R15))

    @r15.setter
    def r15(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R15, value)

    @property
    def st0(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ST0))

    @st0.setter
    def st0(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ST0, value)

    @property
    def st1(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ST1))

    @st1.setter
    def st1(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ST1, value)

    @property
    def st2(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ST2))

    @st2.setter
    def st2(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ST2, value)

    @property
    def st3(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ST3))

    @st3.setter
    def st3(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ST3, value)

    @property
    def st4(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ST4))

    @st4.setter
    def st4(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ST4, value)

    @property
    def st5(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ST5))

    @st5.setter
    def st5(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ST5, value)

    @property
    def st6(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ST6))

    @st6.setter
    def st6(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ST6, value)

    @property
    def st7(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ST7))

    @st7.setter
    def st7(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ST7, value)

    @property
    def xmm0(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM0))

    @xmm0.setter
    def xmm0(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM0, value)

    @property
    def xmm1(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM1))

    @xmm1.setter
    def xmm1(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM1, value)

    @property
    def xmm2(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM2))

    @xmm2.setter
    def xmm2(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM2, value)

    @property
    def xmm3(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM3))

    @xmm3.setter
    def xmm3(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM3, value)

    @property
    def xmm4(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM4))

    @xmm4.setter
    def xmm4(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM4, value)

    @property
    def xmm5(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM5))

    @xmm5.setter
    def xmm5(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM5, value)

    @property
    def xmm6(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM6))

    @xmm6.setter
    def xmm6(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM6, value)

    @property
    def xmm7(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM7))

    @xmm7.setter
    def xmm7(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM7, value)

    @property
    def xmm8(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM8))

    @xmm8.setter
    def xmm8(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM8, value)

    @property
    def xmm9(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM9))

    @xmm9.setter
    def xmm9(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM9, value)

    @property
    def xmm10(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM10))

    @xmm10.setter
    def xmm10(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM10, value)

    @property
    def xmm11(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM11))

    @xmm11.setter
    def xmm11(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM11, value)

    @property
    def xmm12(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM12))

    @xmm12.setter
    def xmm12(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM12, value)

    @property
    def xmm13(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM13))

    @xmm13.setter
    def xmm13(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM13, value)

    @property
    def xmm14(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM14))

    @xmm14.setter
    def xmm14(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM14, value)

    @property
    def xmm15(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM15))

    @xmm15.setter
    def xmm15(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM15, value)

    @property
    def xmm16(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM16))

    @xmm16.setter
    def xmm16(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM16, value)

    @property
    def xmm17(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM17))

    @xmm17.setter
    def xmm17(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM17, value)

    @property
    def xmm18(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM18))

    @xmm18.setter
    def xmm18(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM18, value)

    @property
    def xmm19(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM19))

    @xmm19.setter
    def xmm19(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM19, value)

    @property
    def xmm20(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM20))

    @xmm20.setter
    def xmm20(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM20, value)

    @property
    def xmm21(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM21))

    @xmm21.setter
    def xmm21(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM21, value)

    @property
    def xmm22(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM22))

    @xmm22.setter
    def xmm22(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM22, value)

    @property
    def xmm23(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM23))

    @xmm23.setter
    def xmm23(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM23, value)

    @property
    def xmm24(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM24))

    @xmm24.setter
    def xmm24(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM24, value)

    @property
    def xmm25(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM25))

    @xmm25.setter
    def xmm25(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM25, value)

    @property
    def xmm26(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM26))

    @xmm26.setter
    def xmm26(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM26, value)

    @property
    def xmm27(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM27))

    @xmm27.setter
    def xmm27(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM27, value)

    @property
    def xmm28(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM28))

    @xmm28.setter
    def xmm28(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM28, value)

    @property
    def xmm29(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM29))

    @xmm29.setter
    def xmm29(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM29, value)

    @property
    def xmm30(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM30))

    @xmm30.setter
    def xmm30(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM30, value)

    @property
    def xmm31(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_XMM31))

    @xmm31.setter
    def xmm31(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_XMM31, value)

    @property
    def ymm0(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM0))

    @ymm0.setter
    def ymm0(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM0, value)

    @property
    def ymm1(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM1))

    @ymm1.setter
    def ymm1(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM1, value)

    @property
    def ymm2(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM2))

    @ymm2.setter
    def ymm2(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM2, value)

    @property
    def ymm3(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM3))

    @ymm3.setter
    def ymm3(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM3, value)

    @property
    def ymm4(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM4))

    @ymm4.setter
    def ymm4(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM4, value)

    @property
    def ymm5(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM5))

    @ymm5.setter
    def ymm5(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM5, value)

    @property
    def ymm6(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM6))

    @ymm6.setter
    def ymm6(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM6, value)

    @property
    def ymm7(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM7))

    @ymm7.setter
    def ymm7(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM7, value)

    @property
    def ymm8(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM8))

    @ymm8.setter
    def ymm8(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM8, value)

    @property
    def ymm9(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM9))

    @ymm9.setter
    def ymm9(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM9, value)

    @property
    def ymm10(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM10))

    @ymm10.setter
    def ymm10(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM10, value)

    @property
    def ymm11(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM11))

    @ymm11.setter
    def ymm11(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM11, value)

    @property
    def ymm12(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM12))

    @ymm12.setter
    def ymm12(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM12, value)

    @property
    def ymm13(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM13))

    @ymm13.setter
    def ymm13(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM13, value)

    @property
    def ymm14(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM14))

    @ymm14.setter
    def ymm14(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM14, value)

    @property
    def ymm15(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM15))

    @ymm15.setter
    def ymm15(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM15, value)

    @property
    def ymm16(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM16))

    @ymm16.setter
    def ymm16(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM16, value)

    @property
    def ymm17(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM17))

    @ymm17.setter
    def ymm17(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM17, value)

    @property
    def ymm18(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM18))

    @ymm18.setter
    def ymm18(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM18, value)

    @property
    def ymm19(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM19))

    @ymm19.setter
    def ymm19(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM19, value)

    @property
    def ymm20(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM20))

    @ymm20.setter
    def ymm20(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM20, value)

    @property
    def ymm21(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM21))

    @ymm21.setter
    def ymm21(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM21, value)

    @property
    def ymm22(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM22))

    @ymm22.setter
    def ymm22(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM22, value)

    @property
    def ymm23(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM23))

    @ymm23.setter
    def ymm23(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM23, value)

    @property
    def ymm24(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM24))

    @ymm24.setter
    def ymm24(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM24, value)

    @property
    def ymm25(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM25))

    @ymm25.setter
    def ymm25(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM25, value)

    @property
    def ymm26(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM26))

    @ymm26.setter
    def ymm26(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM26, value)

    @property
    def ymm27(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM27))

    @ymm27.setter
    def ymm27(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM27, value)

    @property
    def ymm28(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM28))

    @ymm28.setter
    def ymm28(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM28, value)

    @property
    def ymm29(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM29))

    @ymm29.setter
    def ymm29(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM29, value)

    @property
    def ymm30(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM30))

    @ymm30.setter
    def ymm30(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM30, value)

    @property
    def ymm31(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_YMM31))

    @ymm31.setter
    def ymm31(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_YMM31, value)

    @property
    def zmm0(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM0))

    @zmm0.setter
    def zmm0(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM0, value)

    @property
    def zmm1(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM1))

    @zmm1.setter
    def zmm1(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM1, value)

    @property
    def zmm2(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM2))

    @zmm2.setter
    def zmm2(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM2, value)

    @property
    def zmm3(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM3))

    @zmm3.setter
    def zmm3(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM3, value)

    @property
    def zmm4(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM4))

    @zmm4.setter
    def zmm4(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM4, value)

    @property
    def zmm5(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM5))

    @zmm5.setter
    def zmm5(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM5, value)

    @property
    def zmm6(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM6))

    @zmm6.setter
    def zmm6(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM6, value)

    @property
    def zmm7(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM7))

    @zmm7.setter
    def zmm7(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM7, value)

    @property
    def zmm8(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM8))

    @zmm8.setter
    def zmm8(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM8, value)

    @property
    def zmm9(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM9))

    @zmm9.setter
    def zmm9(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM9, value)

    @property
    def zmm10(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM10))

    @zmm10.setter
    def zmm10(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM10, value)

    @property
    def zmm11(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM11))

    @zmm11.setter
    def zmm11(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM11, value)

    @property
    def zmm12(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM12))

    @zmm12.setter
    def zmm12(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM12, value)

    @property
    def zmm13(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM13))

    @zmm13.setter
    def zmm13(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM13, value)

    @property
    def zmm14(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM14))

    @zmm14.setter
    def zmm14(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM14, value)

    @property
    def zmm15(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM15))

    @zmm15.setter
    def zmm15(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM15, value)

    @property
    def zmm16(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM16))

    @zmm16.setter
    def zmm16(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM16, value)

    @property
    def zmm17(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM17))

    @zmm17.setter
    def zmm17(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM17, value)

    @property
    def zmm18(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM18))

    @zmm18.setter
    def zmm18(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM18, value)

    @property
    def zmm19(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM19))

    @zmm19.setter
    def zmm19(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM19, value)

    @property
    def zmm20(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM20))

    @zmm20.setter
    def zmm20(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM20, value)

    @property
    def zmm21(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM21))

    @zmm21.setter
    def zmm21(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM21, value)

    @property
    def zmm22(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM22))

    @zmm22.setter
    def zmm22(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM22, value)

    @property
    def zmm23(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM23))

    @zmm23.setter
    def zmm23(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM23, value)

    @property
    def zmm24(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM24))

    @zmm24.setter
    def zmm24(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM24, value)

    @property
    def zmm25(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM25))

    @zmm25.setter
    def zmm25(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM25, value)

    @property
    def zmm26(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM26))

    @zmm26.setter
    def zmm26(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM26, value)

    @property
    def zmm27(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM27))

    @zmm27.setter
    def zmm27(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM27, value)

    @property
    def zmm28(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM28))

    @zmm28.setter
    def zmm28(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM28, value)

    @property
    def zmm29(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM29))

    @zmm29.setter
    def zmm29(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM29, value)

    @property
    def zmm30(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM30))

    @zmm30.setter
    def zmm30(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM30, value)

    @property
    def zmm31(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_ZMM31))

    @zmm31.setter
    def zmm31(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_ZMM31, value)

    @property
    def r8b(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R8B))

    @r8b.setter
    def r8b(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R8B, value)

    @property
    def r9b(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R9B))

    @r9b.setter
    def r9b(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R9B, value)

    @property
    def r10b(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R10B))

    @r10b.setter
    def r10b(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R10B, value)

    @property
    def r11b(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R11B))

    @r11b.setter
    def r11b(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R11B, value)

    @property
    def r12b(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R12B))

    @r12b.setter
    def r12b(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R12B, value)

    @property
    def r13b(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R13B))

    @r13b.setter
    def r13b(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R13B, value)

    @property
    def r14b(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R14B))

    @r14b.setter
    def r14b(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R14B, value)

    @property
    def r15b(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R15B))

    @r15b.setter
    def r15b(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R15B, value)

    @property
    def r8d(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R8D))

    @r8d.setter
    def r8d(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R8D, value)

    @property
    def r9d(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R9D))

    @r9d.setter
    def r9d(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R9D, value)

    @property
    def r10d(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R10D))

    @r10d.setter
    def r10d(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R10D, value)

    @property
    def r11d(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R11D))

    @r11d.setter
    def r11d(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R11D, value)

    @property
    def r12d(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R12D))

    @r12d.setter
    def r12d(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R12D, value)

    @property
    def r13d(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R13D))

    @r13d.setter
    def r13d(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R13D, value)

    @property
    def r14d(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R14D))

    @r14d.setter
    def r14d(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R14D, value)

    @property
    def r15d(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R15D))

    @r15d.setter
    def r15d(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R15D, value)

    @property
    def r8w(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R8W))

    @r8w.setter
    def r8w(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R8W, value)

    @property
    def r9w(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R9W))

    @r9w.setter
    def r9w(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R9W, value)

    @property
    def r10w(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R10W))

    @r10w.setter
    def r10w(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R10W, value)

    @property
    def r11w(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R11W))

    @r11w.setter
    def r11w(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R11W, value)

    @property
    def r12w(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R12W))

    @r12w.setter
    def r12w(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R12W, value)

    @property
    def r13w(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R13W))

    @r13w.setter
    def r13w(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R13W, value)

    @property
    def r14w(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R14W))

    @r14w.setter
    def r14w(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R14W, value)

    @property
    def r15w(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_R15W))

    @r15w.setter
    def r15w(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_R15W, value)

    @property
    def idtr(self) -> GlobalMemoryManagementRegisterWrapper:
        return GlobalMemoryManagementRegisterWrapper(self.__uc, unicorn.x86_const.UC_X86_REG_IDTR)

    @idtr.setter
    def idtr(self, value: tuple[int, int]) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_IDTR, (0, *value, 0))

    @property
    def gdtr(self) -> GlobalMemoryManagementRegisterWrapper:
        return GlobalMemoryManagementRegisterWrapper(self.__uc, unicorn.x86_const.UC_X86_REG_GDTR)

    @gdtr.setter
    def gdtr(self, value: tuple[int, int]) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_GDTR, (0, *value, 0))

    @property
    def ldtr(self) -> LocalMemoryManagementRegisterWrapper:
        return LocalMemoryManagementRegisterWrapper(self.__uc, unicorn.x86_const.UC_X86_REG_LDTR)

    @ldtr.setter
    def ldtr(self, value: tuple[int, int, int, int]) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_LDTR, value)

    @property
    def tr(self) -> LocalMemoryManagementRegisterWrapper:
        return LocalMemoryManagementRegisterWrapper(self.__uc, unicorn.x86_const.UC_X86_REG_TR)

    @tr.setter
    def tr(self, value: tuple[int, int, int, int]) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_TR, value)

    @property
    def fpcw(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_FPCW))

    @fpcw.setter
    def fpcw(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FPCW, value)

    @property
    def fptag(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_FPTAG))

    @fptag.setter
    def fptag(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FPTAG, value)

    @property
    def msr(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_MSR))

    @msr.setter
    def msr(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_MSR, value)

    @property
    def mxcsr(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_MXCSR))

    @mxcsr.setter
    def mxcsr(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_MXCSR, value)

    @property
    def fs_base(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_FS_BASE))

    @fs_base.setter
    def fs_base(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FS_BASE, value)

    @property
    def gs_base(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_GS_BASE))

    @gs_base.setter
    def gs_base(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_GS_BASE, value)

    @property
    def flags(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_FLAGS))

    @flags.setter
    def flags(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FLAGS, value)

    @property
    def rflags(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_RFLAGS))

    @rflags.setter
    def rflags(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_RFLAGS, value)

    @property
    def fip(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_FIP))

    @fip.setter
    def fip(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FIP, value)

    @property
    def fcs(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_FCS))

    @fcs.setter
    def fcs(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FCS, value)

    @property
    def fdp(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_FDP))

    @fdp.setter
    def fdp(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FDP, value)

    @property
    def fds(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_FDS))

    @fds.setter
    def fds(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FDS, value)

    @property
    def fop(self) -> int:
        return cast(int, self.__uc.reg_read(unicorn.x86_const.UC_X86_REG_FOP))

    @fop.setter
    def fop(self, value: int) -> None:
        self.__uc.reg_write(unicorn.x86_const.UC_X86_REG_FOP, value)

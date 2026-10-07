OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kernel_main)
PHDRS { requests PT_LOAD; text PT_LOAD; rodata PT_LOAD; data PT_LOAD; }
SECTIONS {
    . = 0xffffffff80000000;
    .limine_requests : { KEEP(*(.limine_requests_start)) KEEP(*(.limine_requests)) KEEP(*(.limine_requests_end)) } :requests
    . = ALIGN(4096);
    .text : { *(.text .text.*) } :text
    . = ALIGN(4096);
    .rodata : { *(.rodata .rodata.*) } :rodata
    . = ALIGN(4096);
    .data : { *(.data .data.*) } :data
    .bss : { *(COMMON) *(.bss .bss.*) } :data
    /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment*) }
}

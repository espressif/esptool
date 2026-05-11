"""
Minimal ELF32 builder for esptool elf2image tests.

Writes valid ELF32-LSB files with controlled section addresses and sizes so
tests can target specific layout edge cases (e.g. flash segments ending just
short of an MMU page boundary) without needing a full toolchain build.

pyelftools is intentionally not used here: it is a reader only, with no
ELF-writing support. Hand-rolling the small subset of the ELF spec esptool
actually consumes is simpler than working around that.

ELF spec reference: https://refspecs.linuxfoundation.org/elf/elf.pdf
"""

import struct
from collections import namedtuple

# ELF header constants we use. Names match the ELF spec.
ELFMAG = b"\x7fELF"
EI_CLASS_32 = 1
EI_DATA_LSB = 1
EV_CURRENT = 1
ELFOSABI_SYSV = 0
ET_EXEC = 2

# e_machine values esptool's ELFFile reader accepts.
EM_XTENSA = 0x5E
EM_RISCV = 0xF3
ARCH_TO_MACHINE = {"xtensa": EM_XTENSA, "riscv": EM_RISCV}

# Program header types and flags.
PT_LOAD = 1
PF_X, PF_W, PF_R = 0x1, 0x2, 0x4

# Section header types and flags.
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

# Fixed sizes for ELF32-LSB structures.
ELF_HEADER_SIZE = 52
PHDR_SIZE = 32
SHDR_SIZE = 40

# A section described by the caller. "perm" is one of:
#   "rx" code (.iram/.flash.text)
#   "ro" read-only data (.flash.rodata)
#   "rw" writable data (.dram)
Section = namedtuple("Section", "name vaddr size perm")

# Section permission -> (section-header flags, program-header flags).
PERM_FLAGS = {
    "rx": (SHF_ALLOC | SHF_EXECINSTR, PF_R | PF_X),
    "ro": (SHF_ALLOC, PF_R),
    "rw": (SHF_ALLOC | SHF_WRITE, PF_R | PF_W),
}


def build_elf(out_path, arch, sections, entry=0):
    """Write a minimal ELF32-LSB file to out_path.

    arch:     "xtensa" or "riscv"
    sections: list of (name, vaddr, size_bytes, perm) tuples, where perm is
              "rx", "ro", or "rw". See PERM_FLAGS for the meaning of each.
    entry:    entry point address (often 0 for these tests).

    The output layout is:

        [ELF header] [program headers] [section payloads] [shstrtab]
        [section headers (NULL + one per input section + shstrtab)]
    """
    sections = [Section(*s) for s in sections]
    for s in sections:
        if s.perm not in PERM_FLAGS:
            raise ValueError(f"unknown section perm {s.perm!r} for {s.name!r}")
    if arch not in ARCH_TO_MACHINE:
        raise ValueError(f"unknown arch {arch!r}")

    shstrtab, name_offsets = _build_shstrtab(sections)
    section_offsets, shstrtab_offset, shoff = _compute_offsets(sections, shstrtab)

    elf_header = _build_elf_header(
        arch=arch,
        entry=entry,
        shoff=shoff,
        n_phdrs=len(sections),
        n_shdrs=len(sections) + 2,  # +1 NULL +1 shstrtab
    )
    phdrs = b"".join(_build_phdr(s, off) for s, off in zip(sections, section_offsets))
    payloads = b"".join(_section_payload(s, i) for i, s in enumerate(sections))
    shdrs = _build_null_shdr()
    shdrs += b"".join(
        _build_progbits_shdr(s, name_offsets[s.name], off)
        for s, off in zip(sections, section_offsets)
    )
    shdrs += _build_shstrtab_shdr(
        name_offset=shstrtab.find(b".shstrtab"),
        file_offset=shstrtab_offset,
        size=len(shstrtab),
    )

    with open(out_path, "wb") as f:
        f.write(elf_header)
        f.write(phdrs)
        f.write(payloads)
        f.write(shstrtab)
        f.write(shdrs)


def _build_shstrtab(sections):
    """Build the section name string table and return (table_bytes, name->offset)."""
    table = b"\x00.shstrtab\x00"
    offsets = {}
    for s in sections:
        offsets[s.name] = len(table)
        table += s.name.encode() + b"\x00"
    return table, offsets


def _compute_offsets(sections, shstrtab):
    """Compute file offsets for section payloads, shstrtab, and section headers."""
    cursor = ELF_HEADER_SIZE + len(sections) * PHDR_SIZE
    section_offsets = []
    for s in sections:
        section_offsets.append(cursor)
        cursor += s.size
    shstrtab_offset = cursor
    cursor += len(shstrtab)
    return section_offsets, shstrtab_offset, cursor


def _build_e_ident():
    """Build the 16-byte ELF identification field."""
    ident = ELFMAG + bytes([EI_CLASS_32, EI_DATA_LSB, EV_CURRENT, ELFOSABI_SYSV])
    return ident + b"\x00" * (16 - len(ident))


def _build_elf_header(*, arch, entry, shoff, n_phdrs, n_shdrs):
    """Build the 52-byte ELF32 file header."""
    e_phoff = ELF_HEADER_SIZE  # program headers immediately follow file header
    return _build_e_ident() + struct.pack(
        "<HHIIIIIHHHHHH",
        ET_EXEC,  # e_type
        ARCH_TO_MACHINE[arch],  # e_machine
        EV_CURRENT,  # e_version
        entry,  # e_entry
        e_phoff,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        ELF_HEADER_SIZE,  # e_ehsize
        PHDR_SIZE,  # e_phentsize
        n_phdrs,  # e_phnum
        SHDR_SIZE,  # e_shentsize
        n_shdrs,  # e_shnum
        n_shdrs - 1,  # e_shstrndx (shstrtab is the last section)
    )


def _build_phdr(section, file_offset):
    """Build a 32-byte PT_LOAD program header for the given section."""
    _, p_flags = PERM_FLAGS[section.perm]
    return struct.pack(
        "<IIIIIIII",
        PT_LOAD,  # p_type
        file_offset,  # p_offset
        section.vaddr,  # p_vaddr
        section.vaddr,  # p_paddr
        section.size,  # p_filesz
        section.size,  # p_memsz
        p_flags,  # p_flags
        4,  # p_align
    )


def _section_payload(section, index):
    """Build deterministic, easy-to-recognize data bytes for a section.

    The pattern (vaddr + index + byte_position) lets tests verify that the
    right section landed at the right address with a single equality check.
    """
    return bytes((section.vaddr + index + j) & 0xFF for j in range(section.size))


def _build_null_shdr():
    """Build the mandatory zero-filled first section header."""
    return b"\x00" * SHDR_SIZE


def _build_progbits_shdr(section, name_offset, file_offset):
    """Build a PROGBITS section header pointing at the section's payload bytes."""
    sh_flags, _ = PERM_FLAGS[section.perm]
    return struct.pack(
        "<IIIIIIIIII",
        name_offset,  # sh_name (offset into shstrtab)
        SHT_PROGBITS,  # sh_type
        sh_flags,  # sh_flags
        section.vaddr,  # sh_addr
        file_offset,  # sh_offset
        section.size,  # sh_size
        0,  # sh_link
        0,  # sh_info
        4,  # sh_addralign
        0,  # sh_entsize
    )


def _build_shstrtab_shdr(*, name_offset, file_offset, size):
    """Build the section header that describes the shstrtab itself."""
    return struct.pack(
        "<IIIIIIIIII",
        name_offset,  # sh_name (".shstrtab")
        SHT_STRTAB,  # sh_type
        0,  # sh_flags
        0,  # sh_addr (no in-memory location for strtab)
        file_offset,  # sh_offset
        size,  # sh_size
        0,  # sh_link
        0,  # sh_info
        1,  # sh_addralign
        0,  # sh_entsize
    )

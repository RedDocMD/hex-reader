use core::slice;
use std::{fs::File, io::Write, mem};

use color_eyre::eyre::{self, Context};
use object::elf;

use crate::hex::{AddrRange, HexFile};

const FLASH_DATA_RANGE: AddrRange = AddrRange {
    start: 0x0000_0000,
    end: 0x0000_00BF,
};
const CODE_RANGE: AddrRange = AddrRange {
    start: 0x0000_00C0,
    end: 0x0003_FFFF,
};
const OPT_RANGE: AddrRange = AddrRange {
    start: 0x0101_0008,
    end: 0x0101_0033,
};
const SRAM_RANGE: AddrRange = AddrRange {
    start: 0x4000_0000,
    end: 0x400F_FFFF,
};

const VECTOR_TABLE_END: u32 = 0xC0;

#[derive(Debug, Clone, Copy)]
enum SectionKind {
    Flash,
    Code,
    Opt,
    Sram,
    StrTab,
}

#[derive(Debug)]
struct SectionData {
    range: AddrRange,
    kind: SectionKind,
    name: Vec<u8>,
}

fn range_to_section(range: AddrRange) -> SectionData {
    let (kind, name) = if FLASH_DATA_RANGE.contains_range(range) {
        (SectionKind::Flash, b".flash".to_vec())
    } else if CODE_RANGE.contains_range(range) {
        (SectionKind::Code, b".text".to_vec())
    } else if OPT_RANGE.contains_range(range) {
        (SectionKind::Opt, b".opt".to_vec())
    } else if SRAM_RANGE.contains_range(range) {
        (SectionKind::Sram, b".data".to_vec())
    } else {
        unreachable!("Invalid range: {:?}", range);
    };
    SectionData { range, kind, name }
}

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

#[derive(Debug, Default)]
#[repr(C)]
struct ElfIdent {
    magic: [u8; 4],
    class: u8,
    endian: u8,
    version: u8,
    abi: u8,
    abi_version: u8,
    _pad: [u8; 7],
}

#[derive(Debug, Default)]
#[repr(C)]
struct ElfHeader {
    ident: ElfIdent,
    r#type: u16,
    machine: u16,
    version: u32,
    entry: u32,
    ph_off: u32,
    sh_off: u32,
    flags: u32,
    hdr_size: u16,
    ph_ent_size: u16,
    ph_num: u16,
    sh_ent_size: u16,
    sh_num: u16,
    sh_str_idx: u16,
}

#[derive(Debug, Default)]
#[repr(C)]
struct ProgramHeader {
    r#type: u32,
    offset: u32,
    virt_addr: u32,
    phy_addr: u32,
    file_size: u32,
    mem_size: u32,
    flags: u32,
    align: u32,
}

#[derive(Debug, Default)]
#[repr(C)]
struct SectionHeader {
    name: u32,
    r#type: u32,
    flags: u32,
    addr: u32,
    offset: u32,
    size: u32,
    link: u32,
    info: u32,
    align: u32,
    ent_size: u32,
}

pub fn to_elf_file(hex: &HexFile, path: &str) -> eyre::Result<()> {
    let addr_ranges = hex.address_ranges();
    let mut sections = Vec::new();
    for range in addr_ranges {
        if range.contains(VECTOR_TABLE_END) {
            let (before, after) = range.split(VECTOR_TABLE_END);
            sections.push(range_to_section(before));
            sections.push(range_to_section(after));
        } else {
            sections.push(range_to_section(range));
        }
    }

    let mut elf_data = Vec::new();

    // Create space for header
    elf_data.resize(mem::size_of::<ElfHeader>(), 0);

    let entry_point = hex.start_addr().unwrap_or(0) & 0xFFFF_FFFE;
    let mut hdr = ElfHeader::default();

    // Fill out ident
    hdr.ident.magic = ELF_MAGIC;
    hdr.ident.class = elf::ELFCLASS32;
    hdr.ident.endian = elf::ELFDATA2LSB;
    hdr.ident.version = elf::EV_CURRENT;
    hdr.ident.abi = elf::ELFOSABI_SYSV;
    hdr.ident.abi_version = 0;

    // Fill out parts of header we know
    hdr.r#type = elf::ET_EXEC;
    hdr.machine = elf::EM_ARM;
    hdr.version = elf::EV_CURRENT as u32;
    hdr.entry = entry_point;
    hdr.hdr_size = mem::size_of::<ElfHeader>() as u16;

    // Fill out the sections
    let mut section_offsets = Vec::new();
    for section in &sections {
        let off = elf_data.len();
        let data = hex.data_in_range(section.range);
        elf_data.extend_from_slice(&data);
        section_offsets.push(off);
    }

    // Create name section
    sections.push(SectionData {
        range: AddrRange { start: 0, end: 0 },
        kind: SectionKind::StrTab,
        name: b".shstrtab".to_vec(),
    });

    let start_off = elf_data.len();
    section_offsets.push(elf_data.len());
    elf_data.push(0); // Initial null

    let mut name_section_len = 1;
    let mut section_names = Vec::new();
    for section in &sections {
        section_names.push(elf_data.len() - start_off);
        elf_data.extend_from_slice(&section.name);
        elf_data.push(0); // Null terminator
        name_section_len += section.name.len() + 1;
    }

    hdr.sh_str_idx = sections.len() as u16 - 1;
    sections.last_mut().unwrap().range.end = name_section_len as u32 - 1;

    // Fill up section headers
    hdr.sh_ent_size = mem::size_of::<SectionHeader>() as u16;
    hdr.sh_off = elf_data.len() as u32;
    hdr.sh_num = sections.len() as u16;
    for (i, section) in sections.iter().enumerate() {
        let sec_hdr = SectionHeader {
            name: section_names[i] as u32,
            r#type: if matches!(section.kind, SectionKind::StrTab) {
                elf::SHT_STRTAB
            } else {
                elf::SHT_PROGBITS
            },
            flags: match section.kind {
                SectionKind::Flash => elf::SHF_ALLOC,
                SectionKind::Code => elf::SHF_ALLOC | elf::SHF_EXECINSTR,
                SectionKind::Opt => elf::SHF_ALLOC,
                SectionKind::Sram => elf::SHF_ALLOC | elf::SHF_WRITE,
                SectionKind::StrTab => 0,
            },
            addr: if matches!(section.kind, SectionKind::StrTab) {
                0
            } else {
                section.range.start
            },
            offset: section_offsets[i] as u32,
            size: section.range.size(),
            ..Default::default()
        };
        let sec_hdr_slice = ob_to_slice(&sec_hdr);
        elf_data.extend_from_slice(sec_hdr_slice);
    }

    let hdr_slice = ob_to_slice(&hdr);
    elf_data[..hdr_slice.len()].copy_from_slice(hdr_slice);

    let mut file = File::create(path).with_context(|| format!("Opening {}", path))?;
    file.write_all(&elf_data)?;

    Ok(())
}

fn ob_to_slice<T: Sized>(t: &T) -> &[u8] {
    let len = mem::size_of::<T>();
    let ptr: *const T = t;
    unsafe { slice::from_raw_parts(ptr as *const u8, len) }
}

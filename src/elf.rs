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
}

#[derive(Debug)]
struct SectionData {
    range: AddrRange,
    kind: SectionKind,
}

fn range_to_section(range: AddrRange) -> SectionData {
    let kind = if FLASH_DATA_RANGE.contains_range(range) {
        SectionKind::Flash
    } else if CODE_RANGE.contains_range(range) {
        SectionKind::Code
    } else if OPT_RANGE.contains_range(range) {
        SectionKind::Opt
    } else if SRAM_RANGE.contains_range(range) {
        SectionKind::Sram
    } else {
        unreachable!("Invalid range: {:?}", range);
    };
    SectionData { range, kind }
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

    let hdr_slice = ob_to_slice(&hdr);
    elf_data[..hdr_slice.len()].copy_from_slice(hdr_slice);

    let mut file = File::create(path).with_context(|| format!("Opening {}", path))?;
    file.write_all(&elf_data)?;

    // let mut ob = Object::new(BinaryFormat::Elf, Architecture::Arm, Endianness::Little);
    // for sec in &sections {
    //     let data = self.data_in_range(sec.range);
    //     match sec.kind {
    //         SectionKind::Flash => {
    //             ob.add_subsection(StandardSection::ReadOnlyData, b"vector", &data, 1);
    //         }
    //         SectionKind::Code => {
    //             ob.add_subsection(StandardSection::Text, b"bootloader", &data, 1);
    //         }
    //         SectionKind::Opt => {
    //             ob.add_subsection(StandardSection::ReadOnlyDataWithRel, b"opt", &data, 1);
    //         }
    //         SectionKind::Sram => {
    //             ob.add_subsection(StandardSection::Data, b".sram", &data, 1);
    //         }
    //     }
    // }

    // let elf_data = ob.write()?;
    // let in_elf = FileHeader32::<LittleEndian>::parse(elf_data.as_slice())?;
    // let endian = in_elf.endian()?;

    // let mut out_elf = Vec::new();
    // let mut wtr = object::write::elf::Writer::new(Endianness::Little, false, &mut out_elf);

    // wtr.reserve_file_header();
    // wtr.write_file_header(&object::write::elf::FileHeader {
    //     os_abi: in_elf.e_ident().os_abi,
    //     abi_version: 0,
    //     e_type: in_elf.e_type(endian),
    //     e_machine: in_elf.e_machine(endian),
    //     e_entry: entry_point as u64,
    //     e_flags: in_elf.e_flags(endian),
    // })
    // .unwrap();

    // wtr.reserve_program_headers(4);
    // wtr.write_align_program_headers();
    // wtr.write_program_header(&object::write::elf::ProgramHeader {
    //     p_type: elf::PT_LOAD,
    //     p_flags: elf::PF_X | elf::PF_R,
    //     p_offset: 0x0,
    //     p_vaddr: 0x0,
    //     p_paddr: 0x0,
    //     p_filesz: 0x10,
    //     p_memsz: 0x10,
    //     p_align: 1,
    // });

    Ok(())
}

fn ob_to_slice<T: Sized>(t: &T) -> &[u8] {
    let len = mem::size_of::<T>();
    let ptr: *const T = t;
    unsafe { slice::from_raw_parts(ptr as *const u8, len) }
}

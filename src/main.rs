mod elf;
mod hex;

use argh::FromArgs;
use color_eyre::eyre::{self, Context};
use eyre::eyre;

use std::fs::File;
use std::io::Read;

#[derive(FromArgs, PartialEq, Debug)]
#[argh(description = "Parses a .hex file")]
struct HexReaderArgs {
    #[argh(positional)]
    filename: String,

    #[argh(subcommand)]
    sub: HexReaderSubcommands,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum HexReaderSubcommands {
    PrettyPrint(PrettyPrintCommand),
    AddressRanges(AddrRangesCommand),
    PrintRange(PrintRangeCommand),
    Dump(DumpCommand),
    ToElf(ToElfCommand),
    Entry(EntryCommand),
    Transpose(TransposeCommand),
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(
    subcommand,
    name = "entry",
    description = "Print entry point of hex file"
)]
struct EntryCommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "pretty", description = "Pretty-print hex file")]
struct PrettyPrintCommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(
    subcommand,
    name = "ranges",
    description = "Address ranges in hex file"
)]
struct AddrRangesCommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "to-elf", description = "Convert hex file to ELF")]
struct ToElfCommand {
    #[argh(positional, description = "file to output ELF to")]
    path: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(
    subcommand,
    name = "print",
    description = "Print bytes in the hex file"
)]

struct PrintRangeCommand {
    #[argh(
        option,
        description = "offset to start printing from",
        default = "0",
        from_str_fn(num_decode)
    )]
    offset: u32,

    #[argh(
        option,
        description = "number of bytes to print",
        from_str_fn(num_decode)
    )]
    len: Option<u32>,

    #[argh(
        option,
        description = "number of bytes to cluster as one",
        default = "4"
    )]
    cluster: usize,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "dump", description = "Dump bytes to a file")]
struct DumpCommand {
    #[argh(
        option,
        description = "offset to start printing from",
        default = "0",
        from_str_fn(num_decode)
    )]
    offset: u32,

    #[argh(
        option,
        description = "number of bytes to print",
        from_str_fn(num_decode)
    )]
    len: Option<u32>,

    #[argh(positional)]
    filename: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(
    subcommand,
    name = "transpose",
    description = "Transpose an address range to another address"
)]
struct TransposeCommand {
    #[argh(
        positional,
        description = "start of address range to transpose",
        from_str_fn(num_decode)
    )]
    start: u32,

    #[argh(
        positional,
        description = "address to transpose to",
        from_str_fn(num_decode)
    )]
    dest: u32,

    #[argh(positional, description = "filename to write to")]
    filename: String,
}

fn num_decode(s: &str) -> Result<u32, String> {
    let (s, rad) = if let Some(s) = s.strip_prefix("0x") {
        (s, 16)
    } else if let Some(s) = s.strip_prefix("0b") {
        (s, 2)
    } else if let Some(s) = s.strip_prefix("0o") {
        (s, 8)
    } else {
        (s, 10)
    };
    u32::from_str_radix(s, rad).map_err(|e| e.to_string())
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    let args: HexReaderArgs = argh::from_env();

    let filename = &args.filename;
    let mut file = File::open(filename)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let mut hex_file = hex::Context::new(&contents).into_hex_file()?;

    match args.sub {
        HexReaderSubcommands::PrettyPrint(_) => hex_file.pretty_print(),
        HexReaderSubcommands::AddressRanges(_) => {
            let ranges = hex_file.address_ranges();
            println!("Address Ranges:");
            for range in ranges {
                let size = range.end - range.start + 1;
                println!(
                    "    0x{:08x}-0x{:08x} (Size = 0x{:x})",
                    range.start, range.end, size
                );
            }
        }
        HexReaderSubcommands::PrintRange(cmd) => {
            let ranges = hex_file.address_ranges();
            let mut rem_len = cmd.len;
            for range in ranges {
                if let Some(0) = rem_len {
                    break;
                }
                if range.is_before(cmd.offset) {
                    continue;
                }

                let start = cmd.offset.max(range.start);
                let end = if let Some(rem) = rem_len {
                    range.end.min(start + rem - 1)
                } else {
                    range.end
                };

                println!("\n\n[0x{:08x} - 0x{:08x}]", range.start, range.end);
                hex_file.print_bytes(start, end, cmd.cluster);
                println!();

                rem_len = rem_len.map(|l| l - (end + 1 - start));
            }
        }
        HexReaderSubcommands::Dump(cmd) => {
            use std::io::Write;

            let start = cmd.offset;
            let ranges = hex_file.address_ranges();
            let Some(range) = ranges.iter().find(|r| r.contains(start))
                else { return Err(eyre!("0x{:08x} doesn't belong to any address range", start));};
            let end = if let Some(len) = cmd.len {
                let end = start + len - 1;
                if end > range.end {
                    return Err(eyre!(
                        "Length {} is causing end to go out of address range [0x{:08x} - 0x{:08x}] at 0x{:08x}",
                        len,
                        range.start,
                        range.end,
                        end
                    ));
                }
                end
            } else {
                range.end
            };

            let mut file = File::create(cmd.filename)?;
            let mut buf = [0u8; 1];
            let mut pos = hex_file
                .data()
                .iter()
                .position(|d| d.addr_range().contains(start))
                .unwrap();
            let mut data = hex_file.data_at(pos);
            for addr in start..=end {
                if !data.addr_range().contains(addr) {
                    pos += 1;
                    data = hex_file.data_at(pos);
                }
                buf[0] = data.get_byte(addr);
                file.write_all(&buf)?;
            }
        }
        HexReaderSubcommands::ToElf(cmd) => {
            elf::to_elf_file(&hex_file, &cmd.path)?;
        }
        HexReaderSubcommands::Entry(_) => {
            if let Some(start) = hex_file.start_addr() {
                println!("0x{:08X}", start);
            } else {
                println!("No entry point");
            }
        }
        HexReaderSubcommands::Transpose(cmd) => {
            hex_file.transpose(cmd.start, cmd.dest)?;
            let mut file = File::create(&cmd.filename)
                .with_context(|| format!("Creating file {}", cmd.filename))?;
            hex_file.write(&mut file)?;
        }
    }

    Ok(())
}

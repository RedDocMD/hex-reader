use argh::FromArgs;
use color_eyre::eyre;
use eyre::eyre;
use itertools::Itertools;
use std::fmt::Write;
use std::fs::File;
use std::io::Read;
use std::str::from_utf8;

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
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "pp", description = "Pretty-print hex file")]
struct PrettyPrintCommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(
    subcommand,
    name = "ranges",
    description = "Address ranges in hex file"
)]
struct AddrRangesCommand {}

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

    let hex_file = Context::new(&contents).into_hex_file()?;

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
    }

    Ok(())
}

#[derive(Debug)]
struct HexFile {
    start: Option<StartSegmentAddr>,
    data: Vec<Data>,
}

#[derive(Debug)]
struct AddrRange {
    start: u32,
    end: u32,
}

impl AddrRange {
    fn is_before(&self, addr: u32) -> bool {
        self.start < addr && self.end < addr
    }

    fn contains(&self, addr: u32) -> bool {
        self.start <= addr && self.end >= addr
    }
}

impl HexFile {
    fn print_bytes(&self, start: u32, end: u32, cluster: usize) {
        let mut data = self
            .data
            .iter()
            .find(|d| d.addr_range().contains(start))
            .unwrap();

        const CLUSTER_PER_LINE: usize = 4;
        let mut cluster_cnt = 0;

        for addrs in &(start..=end).chunks(cluster) {
            let addrs = addrs.collect_vec();
            let mut cluster = "".repeat((cluster - addrs.len()) * 2);
            for &addr in addrs.iter().rev() {
                if !data.addr_range().contains(addr) {
                    data = self
                        .data
                        .iter()
                        .find(|d| d.addr_range().contains(addr))
                        .unwrap();
                }
                write!(&mut cluster, "{:02x}", data.get_byte(addr)).ok();
            }

            if cluster_cnt % CLUSTER_PER_LINE == 0 {
                print!("\n{:08x}  ", addrs[0]);
            }
            cluster_cnt += 1;

            print!("{} ", cluster);
        }
        if cluster_cnt % CLUSTER_PER_LINE == 0 {
            println!();
        }
    }

    fn pretty_print(&self) {
        if let Some(start) = &self.start {
            println!(
                "Start Addr: CS = 0x{:04x}, IP = 0x{:04x}\n",
                start.cs, start.ip
            );
        }
        for d in &self.data {
            d.pretty_print();
        }
    }

    fn address_ranges(&self) -> Vec<AddrRange> {
        let (first, rest) = self.data.split_first().unwrap();
        let mut ranges = Vec::new();
        let mut start = first.addr;
        let mut end = first.addr + first.data.len() as u32 - 1;
        for d in rest {
            if d.addr != end + 1 {
                ranges.push(AddrRange { start, end });
                start = d.addr;
            }
            end = d.addr + d.data.len() as u32 - 1;
        }
        ranges.push(AddrRange { start, end });
        ranges
    }
}

struct Context<'a> {
    buf: &'a [u8],
    addr_hi: Option<u16>,
    eof: bool,
    line_idx: usize,
}

impl<'a> Context<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            addr_hi: None,
            eof: false,
            line_idx: 0,
        }
    }
}

impl Context<'_> {
    fn into_hex_file(mut self) -> eyre::Result<HexFile> {
        let mut start = None;
        let mut data = Vec::new();

        loop {
            match self.next_record()? {
                Some(Record::Eof) => break,
                Some(Record::Data(d)) => data.push(d),
                Some(Record::StartSegmentAddr(s)) => {
                    start = Some(s);
                }
                _ => {}
            }
        }

        data.sort_by(|l, r| l.addr.cmp(&r.addr));
        Ok(HexFile { start, data })
    }

    fn next_record(&mut self) -> eyre::Result<Option<Record>> {
        if self.eof {
            if self.has_next_line() {
                return Err(eyre!("Unexpected line after EOF record"));
            } else {
                return Ok(None);
            }
        }
        let addr_hi = self.addr_hi;
        let Some((idx, line)) = self.next_line() else { return Err(eyre!("Unexpected EOF")); };

        if line.is_empty() {
            return Err(eyre!("Line {}: empty line", idx));
        }
        if line[0] != b':' {
            return Err(eyre!("Line {}: doesn't start with ':'", idx));
        }

        let kind = u8::from_str_radix(
            from_utf8(
                line.get(7..=8)
                    .ok_or_else(|| eyre!("Line {}: no kind field", idx))?,
            )?,
            16,
        )?;

        match kind {
            0x00 => {
                let len = u8::from_str_radix(
                    from_utf8(
                        line.get(1..=2)
                            .ok_or_else(|| eyre!("Line {}: no len field", idx))?,
                    )?,
                    16,
                )?;

                let addr = u16::from_str_radix(
                    from_utf8(
                        line.get(3..=6)
                            .ok_or_else(|| eyre!("Line {}: no addr field", idx))?,
                    )?,
                    16,
                )?;

                let mut data = Vec::new();
                data.reserve(len as usize);

                for byte in line[9..].chunks(2).take(len as usize) {
                    let byte = u8::from_str_radix(from_utf8(byte)?, 16)?;
                    data.push(byte);
                }
                if data.len() < len as usize {
                    return Err(eyre!(
                        "Line {}: too few data bytes, expected {} but got {}",
                        idx,
                        len,
                        data.len()
                    ));
                }

                let addr = if let Some(addr_hi) = addr_hi {
                    ((addr_hi as u32) << 16) | addr as u32
                } else {
                    addr as u32
                };

                Ok(Some(Record::Data(Data { data, addr })))
            }
            0x01 => {
                self.eof = true;
                Ok(Some(Record::Eof))
            }
            0x03 => {
                let cs = u16::from_str_radix(
                    from_utf8(
                        line.get(9..=12)
                            .ok_or_else(|| eyre!("Line {}: no CS field", idx))?,
                    )?,
                    16,
                )?;
                let ip = u16::from_str_radix(
                    from_utf8(
                        line.get(13..=16)
                            .ok_or_else(|| eyre!("Line {}: no IP field", idx))?,
                    )?,
                    16,
                )?;
                Ok(Some(Record::StartSegmentAddr(StartSegmentAddr { cs, ip })))
            }
            0x04 => {
                let addr_hi = u16::from_str_radix(
                    from_utf8(
                        line.get(9..=12)
                            .ok_or_else(|| eyre!("Line {}: no addr_hi field", idx))?,
                    )?,
                    16,
                )?;
                self.addr_hi = Some(addr_hi);
                Ok(None)
            }
            _ => Err(eyre!("Line {}: Unknown kind {:02X}", idx, kind)),
        }
    }

    fn next_line(&mut self) -> Option<(usize, &[u8])> {
        if self.buf.is_empty() {
            None
        } else {
            self.line_idx += 1;
            if let Some(idx) = self.buf.iter().position(|&x| x == b'\n') {
                let first = &self.buf[..idx];
                self.buf = &self.buf[idx + 1..];
                Some((self.line_idx, first))
            } else {
                Some((self.line_idx, self.buf))
            }
        }
    }

    fn has_next_line(&self) -> bool {
        !self.buf.is_empty()
    }
}

#[derive(Debug)]
enum Record {
    Data(Data),
    Eof,
    StartSegmentAddr(StartSegmentAddr),
}

#[derive(Debug)]
struct Data {
    data: Vec<u8>,
    addr: u32,
}

impl Data {
    fn pretty_print(&self) {
        print!("Addr: 0x{:08x}, ", self.addr);
        print!("Data: [");
        for (i, byte) in self.data.iter().enumerate() {
            print!("{:02x}", byte);
            if i == self.data.len() - 1 {
                println!("]");
            } else {
                print!(", ");
            }
        }
    }

    fn addr_range(&self) -> AddrRange {
        AddrRange {
            start: self.addr,
            end: self.addr + self.data.len() as u32 - 1,
        }
    }

    fn get_byte(&self, addr: u32) -> u8 {
        self.data[(addr - self.addr) as usize]
    }
}

#[derive(Debug)]
struct StartSegmentAddr {
    cs: u16,
    ip: u16,
}

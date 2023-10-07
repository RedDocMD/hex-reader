use color_eyre::eyre;
use eyre::eyre;
use itertools::Itertools;
use std::{fmt, io, str::from_utf8};

#[derive(Debug)]
pub struct HexFile {
    start: Option<StartSegmentAddr>,
    data: Vec<Data>,
}

#[derive(Debug, Clone, Copy)]
pub struct AddrRange {
    pub start: u32,
    pub end: u32,
}

impl AddrRange {
    pub fn is_before(&self, addr: u32) -> bool {
        self.start < addr && self.end < addr
    }

    pub fn contains(&self, addr: u32) -> bool {
        self.start <= addr && self.end >= addr
    }

    pub fn contains_range(&self, range: AddrRange) -> bool {
        self.start <= range.start && self.end >= range.end
    }

    pub fn overlaps_range(&self, range: AddrRange) -> bool {
        self.contains(range.start) || self.contains(range.end)
    }

    pub fn split(&self, at: u32) -> (AddrRange, AddrRange) {
        if at <= self.start || at >= self.end {
            panic!(
                "Cannot split at {} on range {}-{}",
                at, self.start, self.end
            );
        }
        let before = AddrRange {
            start: self.start,
            end: at - 1,
        };
        let after = AddrRange {
            start: at,
            end: self.end,
        };
        (before, after)
    }

    pub fn size(&self) -> u32 {
        self.end - self.start + 1
    }

    pub fn transpose(&self, dest: u32) -> Self {
        if dest >= self.start {
            let diff = dest - self.start;
            Self {
                start: dest,
                end: self.end + diff,
            }
        } else {
            let diff = self.start - dest;
            Self {
                start: dest,
                end: self.end - diff,
            }
        }
    }
}

impl fmt::Display for AddrRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}-0x{:08X}", self.start, self.end)
    }
}

impl HexFile {
    pub fn print_bytes(&self, start: u32, end: u32, cluster: usize) {
        use std::fmt::Write;

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

    pub fn pretty_print(&self) {
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

    pub fn address_ranges(&self) -> Vec<AddrRange> {
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

    pub fn data(&self) -> &[Data] {
        &self.data
    }

    pub fn data_at(&self, idx: usize) -> &Data {
        &self.data[idx]
    }

    pub fn data_in_range(&self, range: AddrRange) -> Vec<u8> {
        let mut data = Vec::new();
        for d in &self.data {
            let curr_range = d.addr_range();
            if range.contains_range(curr_range) {
                data.extend_from_slice(&d.data);
            }
        }
        data
    }

    pub fn start_addr(&self) -> Option<u32> {
        self.start.map(|ss| ((ss.cs as u32) << 16) | (ss.ip as u32))
    }

    pub fn transpose(&mut self, start: u32, dest: u32) -> eyre::Result<()> {
        let ranges = self.address_ranges();
        let src_range = ranges
            .iter()
            .find(|x| x.start == start)
            .ok_or(eyre!("0x{:08X} doesn't start any range", start))?;
        let dest_range = src_range.transpose(dest);
        if let Some(overlap_range) = ranges.iter().find(|x| x.overlaps_range(dest_range)) {
            return Err(eyre!(
                "Destination range {} overlaps with existing range {}",
                dest_range,
                overlap_range
            ));
        }
        for data in &mut self.data {
            if src_range.contains(data.addr) {
                data.transpose(dest);
            }
        }
        Ok(())
    }
}

pub struct Context<'a> {
    buf: &'a [u8],
    addr_hi: Option<u16>,
    eof: bool,
    line_idx: usize,
}

impl<'a> Context<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            addr_hi: None,
            eof: false,
            line_idx: 0,
        }
    }
}

impl Context<'_> {
    pub fn into_hex_file(mut self) -> eyre::Result<HexFile> {
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
pub struct Data {
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

    pub fn addr_range(&self) -> AddrRange {
        AddrRange {
            start: self.addr,
            end: self.addr + self.data.len() as u32 - 1,
        }
    }

    pub fn get_byte(&self, addr: u32) -> u8 {
        self.data[(addr - self.addr) as usize]
    }

    pub fn transpose(&mut self, dest: u32) {
        self.addr = dest;
    }
}

#[derive(Debug, Clone, Copy)]
struct StartSegmentAddr {
    cs: u16,
    ip: u16,
}

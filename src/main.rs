use color_eyre::eyre;
use eyre::eyre;
use std::fs::File;
use std::io::Read;
use std::str::from_utf8;

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    let args: Vec<_> = std::env::args().collect();
    let filename = &args[1];
    let mut file = File::open(filename)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let mut ctx = Context::new(&contents);
    let mut records = Vec::new();
    while let Some(record) = ctx.next_record()? {
        record.pretty_print();
        records.push(record);
    }

    Ok(())
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
    fn next_record(&mut self) -> eyre::Result<Option<Record>> {
        if self.eof {
            if self.has_next_line() {
                return Err(eyre!("Unexpected line after EOF record"));
            } else {
                return Ok(None);
            }
        }
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

                Ok(Some(Record::Data(Data {
                    data,
                    addr: addr as usize,
                })))
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
    addr: usize,
}

#[derive(Debug)]
struct StartSegmentAddr {
    cs: u16,
    ip: u16,
}

impl Record {
    fn pretty_print(&self) {
        match self {
            Record::Data(d) => {
                print!("Addr: 0x{:08x}, ", d.addr);
                print!("Data: [");
                for (i, byte) in d.data.iter().enumerate() {
                    print!("{:02x}", byte);
                    if i == d.data.len() - 1 {
                        println!("]");
                    } else {
                        print!(", ");
                    }
                }
            }
            Record::Eof => println!("EOF"),
            Record::StartSegmentAddr(ssa) => println!("CS: 0x{:04x}, IP: 0x{:04x}", ssa.cs, ssa.ip),
        }
    }
}

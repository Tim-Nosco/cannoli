//! TODO

use bloom::{BloomFilter, ASMS};
use cannoli::{create_cannoli, Cannoli};
use file_lock::{FileLock, FileOptions};
use std::env;
use std::io::{Read, Seek, Write};
use std::sync::Arc;

enum Operation {
    Exec {
        pc: u64,
    },
    #[allow(dead_code)]
    Read {
        pc: u64,
        addr: u64,
        val: u64,
        sz: u8,
    },
    Write {
        pc: u64,
        addr: u64,
        val: u64,
        sz: u8,
    },
    Mmap {
        base: u64,
        len: u64,
        path: String,
        offset: u64,
    },
}

struct Map {
    start: u64,
    size: u64,
    tainted: BloomFilter,
    seen: BloomFilter,
}

/// The structure we implement [`Cannoli`] for!
struct Tracer {
    reached_snapshot: bool,
    maps: Vec<Map>,
    pages_to_restore: Vec<u64>,
}

struct Context {
    snapshot_addr: u64,
}

impl Tracer {
    // See if an address falls in one of our maps.
    //  If so, return it's index.
    fn check_in_map(&self, addr: u64) -> Option<usize> {
        match self.maps.binary_search_by_key(&addr, |x| x.start) {
            Ok(map_idx) => {
                return Some(map_idx);
            }
            Err(map_idx) => {
                if let Some(map) = map_idx.checked_sub(1).and_then(|x| self.maps.get(x)) {
                    if map.start < addr && map.start + map.size > addr {
                        return Some(map_idx - 1);
                    }
                }
            }
        }
        return None;
    }
}

impl Cannoli for Tracer {
    /// The type emit in the serialized trace
    type Trace = Operation;

    /// Context, the shared, immutable context shared between all threads doing
    /// processing.
    type TidContext = Context;

    type PidContext = ();

    fn init_pid(_: &cannoli::ClientInfo) -> Arc<Self::PidContext> {
        Arc::new(())
    }

    /// Load the file table
    fn init_tid(_pid: &Self::PidContext, _: &cannoli::ClientInfo) -> (Self, Self::TidContext) {
        // Determine where to begin processing based on an environment variable
        let env_addr_result = env::var("SNAPSHOT_ADDR");
        let (should_snapshot, parsed_addr) = if let Ok(env_addr) = env_addr_result {
            (true, u64::from_str_radix(&env_addr, 16).unwrap())
        } else {
            // Default to processing at the beginning
            (false, 0)
        };
        println!("Snapshot at {:#x}", parsed_addr);
        (
            Self {
                reached_snapshot: !should_snapshot,
                maps: Vec::new(),
                pages_to_restore: Vec::new(),
            },
            Context {
                snapshot_addr: parsed_addr,
            },
        )
    }

    /// Convert PCs into file + offset in parallel
    fn exec(
        _pid: &Self::PidContext,
        tid: &Self::TidContext,
        pc: u64,
        trace: &mut Vec<Self::Trace>,
    ) {
        if pc == tid.snapshot_addr {
            trace.push(Operation::Exec { pc: pc });
        }
    }

    /// Trace reads
    fn read(
        _pid: &Self::PidContext,
        _tid: &Self::TidContext,
        pc: u64,
        addr: u64,
        val: u64,
        sz: u8,
        trace: &mut Vec<Self::Trace>,
    ) {
        trace.push(Operation::Read {
            pc: pc,
            addr: addr,
            val,
            sz,
        });
    }

    /// Trace writes
    fn write(
        _pid: &Self::PidContext,
        _tid: &Self::TidContext,
        pc: u64,
        addr: u64,
        val: u64,
        sz: u8,
        trace: &mut Vec<Self::Trace>,
    ) {
        trace.push(Operation::Write {
            pc: pc,
            addr: addr,
            val,
            sz,
        });
    }

    fn mmap(
        _pid: &Self::PidContext,
        _tid: &Self::TidContext,
        base: u64,
        len: u64,
        _anon: bool,
        read: bool,
        write: bool,
        _exec: bool,
        path: &str,
        offset: u64,
        trace: &mut Vec<Self::Trace>,
    ) {
        // We only care about operations if they occur in a RW mapping
        if read && write {
            trace.push(Operation::Mmap {
                base: base,
                len: len,
                path: path.to_string(),
                offset: offset,
            });
        }
    }

    // Print the trace
    //  A lot of processing happens in this sequentially blocked function, but most of that
    //   is because mmap is allso called in parallel
    fn trace(&mut self, _pid: &Self::PidContext, _tid: &Self::TidContext, trace: &[Self::Trace]) {
        for op in trace {
            match op {
                Operation::Exec { pc } => {
                    println!("\x1b[0;34mEXEC\x1b[0m   @ {pc:#x}");
                    self.reached_snapshot = true;
                }
                Operation::Read {
                    pc: _,
                    addr,
                    val: _,
                    sz,
                } => {
                    if !self.reached_snapshot {
                        continue;
                    }
                    if let Some(map_idx) = self.check_in_map(*addr) {
                        let mut tainted = false;
                        // Check that all the bytes were previously written
                        for offset in 0..*sz {
                            let byte_addr = *addr + (offset as u64);
                            tainted = tainted | self.maps[map_idx].tainted.contains(&byte_addr);
                            if !tainted {
                                self.maps[map_idx].seen.insert(&byte_addr);
                            }
                        }
                        if !tainted {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    // println!(
                    //     "\x1b[0;32mREAD{sz}\x1b[0m  @ {pc:#x} | \
                    //     {addr:#x} ={val:#x}"
                    // );
                }
                Operation::Write { pc, addr, val, sz } => {
                    if !self.reached_snapshot {
                        continue;
                    }
                    if let Some(map_idx) = self.check_in_map(*addr) {
                        let mut seen = false;
                        for offset in 0..*sz {
                            let byte_addr = *addr + (offset as u64);
                            seen = seen
                                | (self.maps[map_idx].seen.contains(&byte_addr)
                                    & !self.maps[map_idx].tainted.contains(&byte_addr));
                            self.maps[map_idx].tainted.insert(&byte_addr);
                        }
                        if !seen {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    // If we get here, we've found a write that happens after a read
                    //  we should report it to be restored.
                    println!(
                        "\x1b[0;31mWRITE{sz}\x1b[0m @ {pc:#x} | \
                        {addr:#x} ={val:#x}"
                    );
                    let page_start = *addr ^ (*addr & 0xfff);
                    let end_addr = *addr + *sz as u64;
                    let page_end = end_addr ^ (end_addr & 0xfff);
                    // assume that the maximum write size is 256 bytes so we cant
                    //  overlap more than two pages
                    for page in [page_start, page_end].iter() {
                        match self.pages_to_restore.binary_search(page) {
                            Ok(_) => {}
                            Err(idx) => {
                                self.pages_to_restore.insert(idx, *page);
                                println!("{:X?}", self.pages_to_restore);
                            }
                        }
                    }
                }
                Operation::Mmap {
                    base,
                    len,
                    path,
                    offset,
                } => {
                    // Insert the map in sorted order
                    match self.maps.binary_search_by_key(base, |m| m.start) {
                        Ok(_) => {}
                        Err(idx) => {
                            self.maps.insert(
                                idx,
                                Map {
                                    start: *base,
                                    size: *len,
                                    tainted: BloomFilter::with_rate(0.05, 1000000),
                                    seen: BloomFilter::with_rate(0.05, 1000000),
                                },
                            );
                            println!(
                                "\x1b[0;34mMMAP\x1b[0m   {base:#x} {len:#x} {path} {offset:#x}"
                            );
                        }
                    }
                }
            }
        }
    }

    fn finish(&self) {
        println!("Saving...");
        // Open up the save file
        let lock_options = FileOptions::new().read(true).write(true).create(true);
        let mut lock = FileLock::lock("maps.bin", true, lock_options).unwrap();

        // Prepare a place to save our data
        let mut pages_to_restore = self.pages_to_restore.clone();

        // Add all the stuff in the file to our save list
        let original_size = pages_to_restore.len();
        let mut working_value = [0u8; 8];
        while lock.file.read_exact(&mut working_value).is_ok() {
            let addr = u64::from_le_bytes(working_value);
            match pages_to_restore.binary_search(&addr) {
                Ok(_) => {}
                Err(idx) => {
                    pages_to_restore.insert(idx, addr);
                }
            }
        }
        println!(
            "\tAdded {:04} pre-existing values",
            pages_to_restore.len() - original_size
        );

        // Clear the file
        lock.file.rewind().unwrap();
        lock.file.set_len(0).unwrap();

        // Write our data
        println!("\tWriting {:04} total values", pages_to_restore.len());
        for addr in pages_to_restore {
            lock.file.write_all(&addr.to_le_bytes()).unwrap();
        }
        lock.unlock().unwrap();
    }
}

fn main() {
    create_cannoli::<Tracer>(2).unwrap();
}

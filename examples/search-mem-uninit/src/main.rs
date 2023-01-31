//! TODO

use cannoli::{create_cannoli, Cannoli};
use std::env;
use std::sync::Arc;

enum Operation {
    Exec {
        pc: u64,
    },
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
}

/// The structure we implement [`Cannoli`] for!
struct Tracer {
    reached_snapshot: bool,
    maps: Vec<Map>,
}

struct Context {
    snapshot_addr: u64,
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
        let env_addr_result = env::var("SNAPSHOT_ADDR");
        let (should_snapshot, parsed_addr) = if let Ok(env_addr) = env_addr_result {
            (true, u64::from_str_radix(&env_addr, 16).unwrap())
        } else {
            (false, 0)
        };
        println!("Snapshot at {:#x}", parsed_addr);
        (
            Self {
                reached_snapshot: !should_snapshot,
                maps: Vec::new(),
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
        if read && write {
            trace.push(Operation::Mmap {
                base: base,
                len: len,
                path: path.to_string(),
                offset: offset,
            });
        }
    }

    /// Print the trace we processed!
    fn trace(&mut self, _pid: &Self::PidContext, _tid: &Self::TidContext, trace: &[Self::Trace]) {
        for op in trace {
            match op {
                Operation::Exec { pc } => {
                    println!("\x1b[0;34mEXEC\x1b[0m   @ {pc:#x}");
                    self.reached_snapshot = true;
                    // sort the maps
                }
                Operation::Read { pc, addr, val, sz } => {
                    if self.reached_snapshot {
                        println!(
                            "\x1b[0;32mREAD{sz}\x1b[0m  @ {pc:#x} | \
                        {addr:#x} ={val:#x}"
                        );
                    }
                }
                Operation::Write { pc, addr, val, sz } => {
                    if self.reached_snapshot {
                        println!(
                            "\x1b[0;31mWRITE{sz}\x1b[0m @ {pc:#x} | \
                        {addr:#x} ={val:#x}"
                        );
                    }
                }
                Operation::Mmap {
                    base,
                    len,
                    path,
                    offset,
                } => {
                    self.maps.push(Map {
                        start: *base,
                        size: *len,
                    });
                    println!("\x1b[0;34mMMAP\x1b[0m   {base:#x} {len:#x} {path} {offset:#x}");
                }
            }
        }
    }
}

fn main() {
    create_cannoli::<Tracer>(2).unwrap();
}

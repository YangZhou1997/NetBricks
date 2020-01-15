extern crate hyperscan;
extern crate aho_corasick;
use netbricks::common::Result;
use netbricks::packets::ip::v4::Ipv4;
use netbricks::packets::{Ethernet, Packet, RawPacket, Tcp};
use std::str;
use std::io::stdout;
use aho_corasick::AhoCorasick;
use std::fs::File;
use std::cell::RefCell;
use std::io;
use std::io::{BufRead, BufReader, Write};
use hyperscan::*;
// use std::sync::atomic::{AtomicUsize, Ordering};

// const RULE_NUM: usize = (1 << 30); 
const RULE_NUM: usize = 1000; 

fn parse_file(filename: &str) -> Result<Patterns> {
    let f = File::open(filename).unwrap();
    let patterns = io::BufReader::new(f)
        .lines()
        .filter_map(|line: std::result::Result<String, io::Error>| -> Option<Pattern> {
            if let Ok(line) = line {
                let line = line.trim();

                if line.len() > 0 && !line.starts_with('#') {
                    if let Ok(pattern) = Pattern::parse(line) {
                        return Some(pattern);
                    }
                }
            }

            None
        });

    Ok(patterns.collect())
}

pub struct HSC {
    /// Hyperscan compiled database (block mode)
    pub db_block: BlockDatabase,
    /// Hyperscan temporary scratch space (used in both modes)
    pub scratch: RawScratch,
    // Count of matches found during scanning
    // pub match_count: AtomicUsize,
}
impl HSC {
    fn new(db_block: BlockDatabase) -> Result<HSC> {
        let scratch = db_block.alloc().unwrap();
        Ok(HSC {
            db_block: db_block,
            scratch: scratch,
            // match_count: AtomicUsize::new(0),
        })
    }

    fn on_match(_: u32, _: u64, _: u64, _: u32, match_count: &usize) -> u32 {
        // match_count.fetch_add(1, Ordering::Relaxed);
        0
    }

    // Scan each packet (in the ordering given in the PCAP file)
    // through Hyperscan using the block-mode interface.
    fn scan_block(&mut self, payload: &[u8]) {
        if let Err(err) = self.db_block.scan(
            payload,
            0,
            &self.scratch,
            Some(Self::on_match),
            Some(&(0 as usize)),
        ) {
            println!("ERROR: Unable to scan packet. Exiting. {}", err)
        }
    }
}
/* According to my customized pktgen_zeroloss: */
// set pkt_size: 48 includes the 4B pkt_idx, 2B burst_size, and 2B identifier;
// int pkt_size = 48 + sizeof(struct ether_hdr); // 48 + 14 = 62 bytes
// const PAYLOAD_OFFSET: usize = 62; // payload offset relative to the ethernet header.

thread_local! {
    pub static HYPERSCAN: RefCell<HSC> = {
        // do the actual file reading and string handling
        let mut patterns = parse_file("/home/yangz/NetBricks/examples/dpi/rules/hs.rules").unwrap();
        patterns.truncate(RULE_NUM);
        println!("Compiling Hyperscan databases with {} patterns.", patterns.len());
        let db = patterns.build().unwrap();
        RefCell::new(HSC::new(db).unwrap())
    };
}

pub fn dpi(packet: RawPacket) -> Result<Tcp<Ipv4>> {
    let mut ethernet = packet.parse::<Ethernet>()?;
    ethernet.swap_addresses();
    let v4 = ethernet.parse::<Ipv4>()?;
    let tcp = v4.parse::<Tcp<Ipv4>>()?;
    let payload: &[u8] = tcp.get_payload();

    // println!("{}", payload.len());
    // stdout().flush().unwrap();
    
    // let payload_str = match str::from_utf8(&payload[..]) {
    //     Ok(v) => v,
    //     Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    // };
    // from_utf8_unchecked

    // println!("{}", payload_str);
    // stdout().flush().unwrap();

    // let mut matches = vec![];
    // AC.with(|ac| {
    //     for mat in ac.borrow().find_iter(payload) {
    //         matches.push((mat.pattern(), mat.start(), mat.end()));
    //     }
    // });
    HYPERSCAN.with(|hc| {
        hc.borrow_mut().scan_block(payload)
    });
    
    // println!("{:?}", matches);
    // stdout().flush().unwrap();

    Ok(tcp)
}

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
use std::env;
use netbricks::utils::ipsec::*;

const RULE_NUM: usize = (1 << 30); 

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

        let args: Vec<String> = env::args().collect();
        let rule_num: usize = match args.iter().position(|r| r.as_str() == "-r") {
            Some(index) => args[index + 1].parse::<usize>().unwrap(),
            None => RULE_NUM,
        };
        patterns.truncate(rule_num);

        println!("Compiling Hyperscan databases with {} patterns.", patterns.len());
        let db = patterns.build().unwrap();
        RefCell::new(HSC::new(db).unwrap())
    };
}

pub fn dpi(packet: RawPacket) -> Result<Ipv4> {
    let mut ethernet = packet.parse::<Ethernet>()?;
    ethernet.swap_addresses();
    let v4 = ethernet.parse::<Ipv4>()?;
    let payload: &mut [u8] = v4.get_payload_mut(); // payload.len()
    
    let esp_hdr: &mut [u8] = &mut [0u8; 8];
    esp_hdr.copy_from_slice(&payload[0..ESP_HEADER_LENGTH]);

    let decrypted_pkt: &mut [u8] = &mut [0u8; 2000];
    // let decrypted_pkt_len = aes_cbc_sha256_decrypt(payload, decrypted_pkt, false).unwrap();
    let decrypted_pkt_len = aes_gcm128_decrypt_openssl(payload, decrypted_pkt, false).unwrap();
    // let decrypted_pkt_len = aes_gcm128_decrypt_mbedtls(payload, decrypted_pkt, false).unwrap();

    // println!("decrypted_pkt_len: {}", decrypted_pkt_len - ESP_HEADER_LENGTH - AES_CBC_IV_LENGTH);
    // stdout().flush().unwrap();

    HYPERSCAN.with(|hc| {
        hc.borrow_mut().scan_block(payload)
    });

    // let encrypted_pkt_len = aes_cbc_sha256_encrypt(&decrypted_pkt[..(decrypted_pkt_len - ESP_HEADER_LENGTH - AES_CBC_IV_LENGTH)], &(*esp_hdr), payload).unwrap();
    let encrypted_pkt_len = aes_gcm128_encrypt_openssl(&decrypted_pkt[..(decrypted_pkt_len - ESP_HEADER_LENGTH - AES_CBC_IV_LENGTH)], &(*esp_hdr), payload).unwrap();
    // let encrypted_pkt_len = aes_gcm128_encrypt_mbedtls(&decrypted_pkt[..(decrypted_pkt_len - ESP_HEADER_LENGTH - AES_CBC_IV_LENGTH)], &(*esp_hdr), payload).unwrap();

    Ok(v4)
}

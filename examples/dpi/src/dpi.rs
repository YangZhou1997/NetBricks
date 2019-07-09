extern crate aho_corasick;
use netbricks::common::Result;
use netbricks::packets::ip::v4::Ipv4;
use netbricks::packets::{Ethernet, Packet, RawPacket, Tcp};
use std::str;
use std::io::stdout;
use std::io::Write;
use std::sync::Arc;
use std::sync::RwLock;
use aho_corasick::AhoCorasick;
use std::fs::File;
use std::io::{BufRead, BufReader};

const RULE_NUM: usize = (1 << 30); 

/* According to my customized pktgen_zeroloss: */
// set pkt_size: 48 includes the 4B pkt_idx, 2B burst_size, and 2B identifier;
// int pkt_size = 48 + sizeof(struct ether_hdr); // 48 + 14 = 62 bytes
// const PAYLOAD_OFFSET: usize = 62; // payload offset relative to the ethernet header.

lazy_static! {
    static ref AC: Arc<RwLock<AhoCorasick>> = {
        let mut rules = vec![];

        let file = File::open("./dpi/wordrules/word.rules").expect("cannot open file");
        let file = BufReader::new(file);
        for line in file.lines().filter_map(|result| result.ok()){
            // println!("{}", line);
            rules.push(line);
            if rules.len() == RULE_NUM {
                break;
            }
        }

        //let patterns = &["This is", "Yang", "abcedf"];
        let patterns = &rules;
        let m = AhoCorasick::new(patterns);
        Arc::new(RwLock::new(m))
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

    let mut matches = vec![];
    let ac = AC.read().unwrap();
    for mat in ac.find_iter(payload) {
        matches.push((mat.pattern(), mat.start(), mat.end()));
    }
    // println!("{:?}", matches);
    // stdout().flush().unwrap();

    Ok(tcp)
}

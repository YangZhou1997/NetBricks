extern crate netbricks;
#[macro_use]
extern crate lazy_static;
use netbricks::common::Result;
use netbricks::config::load_config;
use netbricks::interface::{PacketRx, PacketTx};
use netbricks::operators::{Batch, ReceiveBatch};
use netbricks::packets::{Ethernet, Packet, RawPacket, Tcp};
use netbricks::runtime::Runtime;
use netbricks::scheduler::Scheduler;
use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::sync::RwLock;
use std::sync::Arc;
use netbricks::packets::ip::v4::Ipv4;

fn install<T, S>(ports: Vec<T>, sched: &mut S)
where
    T: PacketRx + PacketTx + Display + Clone + 'static,
    S: Scheduler + Sized,
{
    for port in &ports {
        println!("Receiving port {}", port);
    }

    let pipelines: Vec<_> = ports
        .iter()
        .map(|port| {
            ReceiveBatch::new(port.clone())
                .map(macswap)
                .send(port.clone())
        })
        .collect();

    println!("Running {} pipelines", pipelines.len());
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}

lazy_static! {
    static ref FILE_HANDLER: Arc<RwLock<File>> = {
        let file = File::create("/home/yangz/NetBricks/examples/dumptrace/trace.txt").unwrap();
        Arc::new(RwLock::new(file))
    };
    static ref FILE_CNT: Arc<RwLock<usize>> = {
        let cnt = 0;
        Arc::new(RwLock::new(cnt))
    };
}


fn macswap(packet: RawPacket) -> Result<Tcp<Ipv4>> {
    let mut ethernet = packet.parse::<Ethernet>()?;
    ethernet.swap_addresses();
    let v4 = ethernet.parse::<Ipv4>()?;
    let tcp = v4.parse::<Tcp<Ipv4>>()?;
    let payload: &[u8] = tcp.get_payload();

    // let mut file = FILE_HANDLER.write().unwrap();
    let mut cnt = FILE_CNT.write().unwrap();
    let file_name = format!("/home/yangz/NetBricks/examples/dumptrace/trace_{}.txt", cnt);
    *cnt += 1;
    *cnt %= 32;

    let mut file = File::create(file_name).unwrap();
    file.write_all(payload).unwrap();
    // println!("dumptrace");

    Ok(tcp)
}

fn main() -> Result<()> {
    let configuration = load_config()?;
    println!("{}", configuration);
    let mut runtime = Runtime::init(&configuration)?;
    runtime.add_pipeline_to_run(install);
    runtime.execute()
}

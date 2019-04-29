#[macro_use]
extern crate log;
extern crate netbricks;
extern crate simplelog;
use log::Level;
use netbricks::common::Result;
use netbricks::config::load_config;
use netbricks::runtime::{Runtime, SIGHUP, SIGTERM};
use simplelog::{Config, LevelFilter, WriteLogger};
use std::fs::File as StdFile;

fn start_logger() -> Result<()> {
    WriteLogger::init(
        LevelFilter::Warn,
        Config {
            time: None,
            level: Some(Level::Error),
            target: Some(Level::Debug),
            location: Some(Level::Trace),
            time_format: None,
        },
        StdFile::create("test.log").unwrap(),
    )
    .map_err(|e| e.into())
}

fn main() -> Result<()> {
    start_logger()?;
    let configuration = load_config()?;
    println!("{}", configuration);
    let mut runtime = Runtime::init(&configuration)?;
    runtime.execute(|signal| match signal {
        SIGHUP => {
            warn!("SIGHUP.");
            Ok(())
        }
        SIGTERM => {
            warn!("SIGTERM.");
            Ok(())
        }
        _ => {
            warn!("unknown signal.");
            Ok(())
        }
    })
}

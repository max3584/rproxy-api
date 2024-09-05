mod lib;
mod api;
mod dns;
mod tcp;
mod udp;

use log::*;
use tokio;
use serde_json;
use std::path::Path;
use argh::FromArgs;
use chrono::Local;
use crate::api::APIServer;

#[allow(dead_code)]
#[derive(FromArgs)]
#[argh(description = "TCP/UDP Forwarder")]
struct Options {
	// loglevel
	#[argh(option, short='l', default="2", description = "log level")]
	loglevel: u8,
	// debug
	#[argh(switch, short='d', description = "debug mode")]
	debug: bool,
	// logfile
	#[argh(option, short='f', default="\"rproxy.log\".to_string()", description = "logging file")]
	logfile: String,
	// api address
	#[argh(option, short='a', default="\"127.0.0.1\".to_string()", description = "api address")]
	api_addr: String,
	// server port
	#[argh(option, short='p', default="8080", description = "server port")]
	api_port: u16,
	// control_tcp_addr
	#[argh(option, short='t', default="\"127.0.0.2\".to_string()", description = "control tcp address")]
	control_tcp_addr: String,
	// control_udp_addr
	#[argh(option, short='u', default="\"127.0.0.3\".to_string()", description = "control udp address")]
	control_udp_addr: String,
}

pub static LOGGER: Logger = Logger;

struct Logger;

impl log::Log for Logger {
	fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
		true
	}

	fn log(&self, record: &Record) {
		println!("|{}| [{}] {}", Local::now().format("%Y-%m-%d %H:%M:%S"), record.level(), record.args());
	}

	fn flush(&self) { todo!() }
}

#[tokio::main]
async fn main() {
    let options: Options = argh::from_env::<Options>();

    if Path::new(&options.logfile).exists() {
		std::fs::remove_file(&options.logfile)
			.unwrap_or_else(|e| {
				error!("Failed to remove log file: {}", e);
				std::process::exit(1);
			});
	} else {
		log::set_logger(&LOGGER).unwrap();
		if options.debug {
			log::set_max_level(LevelFilter::Debug);
		} else {
			log::set_max_level(LevelFilter::Info);
		}
	}

    info!("Starting application...");


    // IPC Controller Config
    let config = APIServer {
        server: options.api_addr,
        port: options.api_port,
        control_tcp_addr: options.control_tcp_addr,
        control_udp_addr: options.control_udp_addr,
    };

    config.start().await;

}
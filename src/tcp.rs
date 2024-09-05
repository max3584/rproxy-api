use log::*;
use std::sync::{Arc, Mutex};
use futures::future::try_join;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;
use tokio::net::TcpStream;
use tokio::net::TcpListener;
use tokio::time;
use serde_json;
use crate::dns::DNSResolve;
use crate::api::sync;

struct TCPPeerPair {
	client: TcpStream,
	remote: String,
}

impl TCPPeerPair {
	async fn run(mut self) -> Result<(), std::io::Error>{
		// let mut outbound = TcpStream::connect(self.remote.clone()).await?;

		// let (mut ri, mut wi) = self.client.split();
		// let (mut ro, mut wo) = outbound.split();

		// let client_to_server = async {
		//     tokio::io::copy(&mut ri, &mut wo).await?;
		//     wo.shutdown().await
		// };

		// let server_to_client = async {
		//     tokio::io::copy(&mut ro, &mut wi).await?;
		//     wi.shutdown().await
		// };
		// try_join(client_to_server, server_to_client).await?;
		let mut outbound = TcpStream::connect(self.remote.clone()).await?;
		match tokio::io::copy_bidirectional(&mut self.client, &mut outbound).await {
			Ok(tx) => {
				info!("[TCP] [Proxy] Copy data: {:?}", tx);
			},
			Err(e) => {
				error!("[TCP] [PROXY] Failed to copy data: {:?}", e);
			}
		}
		outbound.shutdown().await?;
		self.client.shutdown().await?;
		Ok(())
	}
}
pub struct TCPProxy {
	pub signal_addr: String,
	pub addr: String,
	pub remote: Arc<Mutex<String>>,
	pub stop: Arc<Mutex<bool>>,
	pub dns: Vec<String>
}

impl DNSResolve for TCPProxy {
	fn remote(&self) -> String {
		let remote = format!("{}", self.remote.lock().unwrap());
		return remote;
	}
	fn client(&self) -> &String{
		&self.addr
	}
	fn dns(&self) -> &Vec<String>{
		&self.dns
	}
	fn reset_dns(&mut self,d: &Vec<String>) -> usize {
		self.dns = d.to_vec();
		self.dns.len()
	}
}

impl TCPProxy {
	pub fn new(signal_addr: String, addr: String, remote: String) -> Self {
		Self {
			signal_addr: signal_addr,
			addr: addr,
			remote: Arc::new(Mutex::new(remote)),
			stop: Arc::new(Mutex::new(false)),
			dns: vec![]
		}
	}

	pub async fn run(mut self) -> Result<(), std::io::Error> {
		self.resolve().await.unwrap();
		let stop_signal = Arc::clone(&self.stop);
		let remote_signal = Arc::clone(&self.remote);

		let bind_addr = self.addr.clone();
		let remote = self.remote.clone();
		let signal_addr = self.signal_addr.clone();

		info!("[TCP] Starting Proxy {} <-> {}", &bind_addr, &remote.lock().unwrap());
		let main_task = async move {
			let mut time_out1 = time::interval(tokio::time::Duration::from_secs(30));
			let mut host = self.dns[0].clone();

			match TcpListener::bind(&bind_addr).await {
				Ok(listener) => {
					info!("[TCP] Listening on {}", &listener.local_addr().unwrap());
					loop{
						tokio::select!{
							x = listener.accept() => {
								match x {
									Ok((inbound, _)) => {
										let client = TCPPeerPair{
											client: inbound,
											remote: host.clone()
										};
										tokio::spawn(client.run());
									},
									Err(e1) => {
										error!("[TCP] Failed to accept new connection from {}, err={:?}", &bind_addr, e1);
									}
								}
							},
							_ = time_out1.tick() => {
								debug!("Ressolve DNS update");
								if *self.stop.lock().unwrap() {
										break;
								}
								self.resolve().await.unwrap();
								host = self.dns[0].clone();
							}
						}
					}
					Ok::<(),std::io::Error>(())
				},
				Err(e) => {
					error!("[TCP] Failed to bind interface {}, err={:?}", &bind_addr, e);
					Ok(())
				}
			}
		};

		info!("[IPC] [TCP] Controller is running on port {}", signal_addr);
		let control = async move {
			sync(signal_addr, remote_signal, stop_signal).await;
			Ok(())
		};
		let _ = try_join(main_task, control).await.unwrap();
		Ok(())
	}
}

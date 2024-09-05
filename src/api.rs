use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use serde_json;
use log::*;
use tokio;
use crate::lib::{APICommand, Command};
use crate::tcp::TCPProxy;
use crate::udp::UDPProxy;


pub struct APIServer {
	pub server: String,
	pub port: u16,
	pub control_tcp_addr: String,
	pub control_udp_addr: String
}

impl APIServer {
	pub async fn start(&self) {
		let api_server = format!("{}:{}", &self.server, &self.port);
		info!("[API] Starting API Server on {}", &api_server);
		match TcpListener::bind(&api_server).await {
			Ok(listener) => {
				loop {
					match listener.accept().await {
						Ok((stream, _)) => {
							if let Err(e) = stream.readable().await {
								error!("[API] Failed to read from stream: {}", e);
								continue;
							};
							let mut buffer = [0; 1024];
							match stream.try_read(&mut buffer) {
								Ok(n) => {
									let receive_data = String::from_utf8_lossy(&buffer[..n]).to_string();
									match serde_json::from_str::<APICommand>(&receive_data) {
										Ok(command) => {
											match command.property.as_str() {
												"UP" => {
													let listen_addr = format!("{}:{}", &command.listen_addr, &command.listen_port);
													let remote_addr = format!("{}:{}", &command.remote_addr, &command.remote_port);
													let protocol = &command.protocol;
													match protocol.as_str() {
														"TCP" => {
															info!("[API] Starting TCP Proxy {} -> {}", &listen_addr, &remote_addr);
															let tcp_proxy = TCPProxy::new(format!("{}:{}", self.control_tcp_addr, command.listen_port), listen_addr, remote_addr);
															tokio::spawn(async move {
																tcp_proxy.run().await.unwrap();
															});
														},
														"UDP" => {
															info!("[API] Starting UDP Proxy {} -> {}", &listen_addr, &remote_addr);
															let mut udp_proxy = UDPProxy::new(format!("{}:{}", self.control_udp_addr, command.listen_port), listen_addr, remote_addr);
															tokio::spawn(async move {
																udp_proxy.run().await.unwrap();
															});
														}
														_ => {
															error!("[API] Unsupported protocol: {}", protocol);
														}
													}
												},
												_ => {
													error!("[API] Unknown command: {}", command.property);
												}
											}
										},
										Err(e) => {
											error!("[API] Failed to parse command: {}", e);
										}
									}
								},
								Err(e) => {
									error!("[API] Failed to read from stream: {}", e);
								}
							}
						},
						Err(e) => {
						error!("[API] Failed to accept: {}", e);
						}
					}
				}
			},
			Err(e) => {
					error!("[API] Failed to bind: {}", e);
			}
		}
	}
}

pub async fn sync(signal_addr: String, remote_signal: Arc<Mutex<String>>, stop_signal: Arc<Mutex<bool>>) {
	info!("[IPC] Controller is running on port {}", signal_addr);
	match TcpListener::bind(signal_addr).await {
		Ok(signal_port) => {
			info!("[IPC] Listening on {}", signal_port.local_addr().unwrap());
			loop {
				match signal_port.accept().await {
					Ok((stream, _)) => {
						if let Err(e) = stream.readable().await {
							error!("[IPC] Failed to read from stream: {}", e);
							continue;
						};
						let mut buf = [0; 1024];
						if let Err(e) = stream.readable().await {
							error!("[IPC] Failed to read from stream: {}", e);
							continue;
						};
						match stream.try_read(&mut buf) {
							Ok(n) => {
								let cmd = String::from_utf8_lossy(&buf[..n]);

								match serde_json::from_str::<Command>(&cmd) {
									Ok(command) => {
										match command.property.as_str() {
											"STOP" => {
												info!("[IPC] Stopping Proxy");
												let mut stop = stop_signal.lock().unwrap();
												*stop = true;
												break;
											},
											"UPDATE" => {
												let parameter = command.parameter.unwrap().clone();
												info!("[IPC] Updating remote address {} -> {}", remote_signal.lock().unwrap(), &parameter);
												let mut remote = remote_signal.lock().unwrap();
												*remote = parameter;
											},
											_ => {
												error!("[IPC] Unknown command: {}", command.property);
											}
										}
									},
									Err(e) => {
											error!("[IPC] Failed to parse command: {}", e);
									}
								}
							},
							Err(e) => {
								error!("[IPC] Failed to read from stream: {}", e);
							}
						}
					},
					Err(e) => {
						error!("[IPC] Failed to accept: {}", e);
					}
				}
			}
		},
		Err(e) => {
				error!("[IPC] Failed to bind: {}", e);
		}
	}
}
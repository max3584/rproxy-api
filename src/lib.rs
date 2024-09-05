use serde::Deserialize;


#[derive(Deserialize, Debug)]
pub struct Command {
	pub property: String,
	pub parameter: Option<String>
}

#[derive(Deserialize, Debug)]
pub struct APICommand {
	pub property: String,
	pub listen_addr: String,
	pub listen_port: u16,
	pub remote_addr: String,
	pub remote_port: u16,
	pub protocol: String
}
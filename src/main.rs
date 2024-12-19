use log::{debug, error, info};
use std::{net::Ipv4Addr, sync::LazyLock};
use tokio::net::UdpSocket;

mod packet;

const ECHONET_LITE_PORT: u16 = 3610;
static MULTICAST_ADDR_V4: LazyLock<Ipv4Addr> = LazyLock::new(|| "224.0.23.0".parse().unwrap());

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .default_format()
        .init();

    info!(
        "Establishing connection... (port: {}, multicast_addr: {})",
        ECHONET_LITE_PORT,
        MULTICAST_ADDR_V4.to_string()
    );
    let sock = UdpSocket::bind(("::", ECHONET_LITE_PORT)).await?;
    sock.set_multicast_loop_v4(false)?;
    sock.join_multicast_v4(MULTICAST_ADDR_V4.clone(), Ipv4Addr::UNSPECIFIED)?;

    let mut buf = [0; 1024];
    info!("Listening ECHONET Lite packets...");
    loop {
        tokio::select! {
            res = sock.recv_from(&mut buf) => {
                let (msg, addr) = match res {
                    Ok((len, addr)) => (&buf[..len], addr),
                    Err(e) => {
                        error!("Failed to receive a packet: {:?}", e);
                        continue;
                    }
                };
                let ipv4 = addr.ip().to_canonical();
                debug!("[{}] {:?}", ipv4, msg);
                match packet::Packet::try_from(msg) {
                    Ok(packet) => {
                        info!("[{}] {:?}", ipv4, packet);
                    }
                    Err(e) => {
                        error!("[{}] Failed to parse a packet: {:?}", ipv4, e);
                    }
                }
            }
        }
    }
}

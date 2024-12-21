use log::{debug, error, info, trace, warn};
use std::{
    net::Ipv4Addr,
    sync::{Arc, LazyLock},
};
use tokio::{net::UdpSocket, time};

mod packet;
mod response;

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
    let sock = {
        let s = UdpSocket::bind(("::", ECHONET_LITE_PORT)).await?;
        s.set_multicast_loop_v4(false)?;
        s.join_multicast_v4(MULTICAST_ADDR_V4.clone(), Ipv4Addr::UNSPECIFIED)?;
        Arc::new(s)
    };

    let mut buf = [0; 1024];
    info!("Listening ECHONET Lite packets...");
    let sock_inner = Arc::clone(&sock);
    tokio::spawn(async move {
        // send discovery packet after 1 second sleep
        time::sleep(time::Duration::from_secs(1)).await;
        let packet = packet::Packet::new_discovery_request();
        debug!(
            "discover request (to: {}) {:?}",
            MULTICAST_ADDR_V4.to_string(),
            packet
        );
        let bytes = packet.to_bytes();
        let result = sock_inner
            .send_to(&bytes, (MULTICAST_ADDR_V4.to_string(), ECHONET_LITE_PORT))
            .await;
        if let Err(e) = result {
            error!("Failed to send a packet: {:?}", e);
        }
    });
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
                trace!("{:?} {:?}", addr, msg);
                let ipv4 = addr.ip().to_canonical();
                match packet::Packet::try_from(msg) {
                    Ok(packet) => {
                        debug!("[{}] {:?}", ipv4, packet);
                        if let Ok(r) = response::DiscoveryResponse::try_from(&packet) {
                            info!("[{}] {:?}", ipv4, r);
                            for eoj in r.instances {
                                let packet = packet::Packet::new_sync_request(eoj);
                                debug!("sync request (to: {}, eoj: {:?}) {:?}", ipv4, eoj, packet);
                                let bytes = packet.to_bytes();
                                trace!("{}", bytes.iter().map(|b| format!("{:02X}", b)).collect::<String>());
                                if let Err(e) = sock.send_to(&bytes, (ipv4, ECHONET_LITE_PORT)).await {
                                    error!("failed to send a packet (to: {}, eoj: {:?}) {:?}", ipv4, eoj, e);
                                }
                            }
                        } else if let Ok(r) = response::SyncResponse::try_from(&packet) {
                            info!("[{}] {:?}", ipv4, r);
                        } else {
                            warn!(
                                "[{}] Received an unknown packet: {:?}",
                                ipv4, packet
                            );
                        }
                    }
                    Err(e) => {
                        error!("[{}] Failed to parse a packet: {:?}", ipv4, e);
                    }
                }
            }
        }
    }
}

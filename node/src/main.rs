use anyhow::{anyhow, Result};
use clap::{load_yaml, App};
use config::Node;

use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use tokio::sync::{mpsc::{channel, Sender}, oneshot};
use std::{net::{SocketAddr, SocketAddrV4}};

#[tokio::main]
async fn main() -> Result<()> {
    log::error!("{}", std::env::current_dir().unwrap().display());
    let yaml = load_yaml!("cli.yml");
    let m = App::from_yaml(yaml).get_matches();
    //println!("{:?}",m);
    let conf_str = m
        .value_of("config")
        .expect("unable to convert config file into a string");
    let vss_type = m
        .value_of("protocol")
        .expect("Unable to detect protocol to run");
    
    let _syncer_file = m
        .value_of("syncer")
        .expect("Unable to parse syncer ip file");
    let _batches = m
        .value_of("batches")
        .expect("Unable to parse number of batches")
        .parse::<usize>().unwrap();
    let _per_batch = m
        .value_of("per")
        .expect("Unable to parse per batch")
        .parse::<usize>().unwrap();
    let _lin_quad = m
        .value_of("lin")
        .expect("Unable to parse per lin_quad")
        .parse::<bool>().unwrap();
    let _opt_pess = m
        .value_of("opt")
        .expect("Unable to parse per lin_quad")
        .parse::<bool>().unwrap();
    let _ibft = m
        .value_of("ibft")
        .expect("Unable to parse per ibft")
        .parse::<bool>().unwrap();

    // let broadcast_msgs_file = m
    //     .value_of("bfile")
    //     .expect("Unable to parse broadcast messages file");
    // let byz_flag = m.value_of("byz").expect("Unable to parse Byzantine flag");
    // let node_normal: bool = match byz_flag {
    //     "true" => true,
    //     "false" => false,
    //     _ => {
    //         panic!("Byz flag invalid value");
    //     }
    // };
    let conf_file = std::path::Path::new(conf_str);
    let str = String::from(conf_str);
    let mut config = match conf_file
        .extension()
        .expect("Unable to get file extension")
        .to_str()
        .expect("Failed to convert the extension into ascii string")
    {
        "json" => Node::from_json(str),
        "dat" => Node::from_bin(str),
        "toml" => Node::from_toml(str),
        "yaml" => Node::from_yaml(str),
        _ => panic!("Invalid config file extension"),
    };

    simple_logger::SimpleLogger::new()
        .with_utc_timestamps()
        .init()
        .unwrap();
    log::set_max_level(log::LevelFilter::Info);
    config.validate().expect("The decoded config is not valid");
    if let Some(f) = m.value_of("ip") {
        let f_str = f.to_string();
        log::info!("Logging the file f {}", f_str);
        config.update_config(util::io::file_to_ips(f.to_string()));
    }
    let config = config;
    // Start the Reliable Broadcast protocol.
    //
    // `handles` must stay alive for as long as the protocol should run, so it
    // is bound here in `main` rather than inside the match arm: a binding that
    // goes out of scope at the end of the arm would shut the protocol down
    // before we ever reach the signal wait below.
    let handles = match vss_type {
        "ctrbc" => {
            log::info!("Cachin Tessaro RBC protocol");
            spawn(config).await?
        }
        _ => {
            log::error!(
                "Matching Distributed Computing protocol not provided {}, canceling execution",
                vss_type
            );
            return Ok(());
        }
    };

    // Implement a waiting strategy
    let mut signals = Signals::new(&[SIGINT, SIGTERM])?;
    signals.forever().next();
    log::error!("Received termination signal");
    handles.shutdown();
    log::error!("Shutting down server");
    Ok(())
}

pub fn to_socket_address(ip_str: &str, port: u16) -> SocketAddr {
    let addr = SocketAddrV4::new(ip_str.parse().unwrap(), port);
    addr.into()
}

/// Handles that must outlive the protocol they started.
///
/// Every field here is load-bearing, because each context treats the far end of
/// these channels as a shutdown signal:
///
/// * dropping an entry of `exit_handles` resolves that context's exit receiver
///   with `RecvError`, which its run loop reports as `Consensus error: channel
///   closed` before returning;
/// * dropping `req_send` closes the request channel the context selects on,
///   which it reports as `Networking layer has closed` before returning.
///
/// Either one stops the module within milliseconds of startup, so bind this
/// value in a scope that lives as long as the protocol should. Binding it to
/// `_`, or to a name inside a narrower block, drops it immediately and the
/// module exits before doing any work.
#[must_use = "dropping ProtocolHandles shuts the spawned protocol down immediately"]
pub struct ProtocolHandles {
    /// Issue requests to the module on this channel.
    pub req_send: Sender<Vec<u8>>,
    /// One exit handle per spawned context. Sending on a handle asks that
    /// context to stop; dropping one stops it just as abruptly.
    pub exit_handles: Vec<oneshot::Sender<()>>,
}

impl ProtocolHandles {
    /// Ask every spawned context to stop.
    ///
    /// A send failure just means that context already exited, so it is ignored.
    pub fn shutdown(self) {
        for exit in self.exit_handles {
            let _ = exit.send(());
        }
    }
}

/// Wire up and start the CTRBC module.
///
/// The returned [`ProtocolHandles`] owns everything that keeps the protocol
/// alive; see its documentation for why the caller must hold on to it.
pub async fn spawn(config: Node) -> Result<ProtocolHandles> {
    // ctrbc_req_send_channel: Request sending channel, request receiving channel. The sending channel can be used to issue message requests to the RBC module.
    // ctrbc_req_recv_channel: Request receiving channel - passed as an argument. The RBC module listens to this channel.
    let (ctrbc_req_send_channel, ctrbc_req_recv_channel) = channel(10000);

    // ctrbc_out_send_channel: Output sending channel - passed as an argument. The RBC module sends outputs on this channel.
    // ctrbc_out_recv_channel: Output receiving channel. We poll this channel to get outputs from RBC module.
    let (ctrbc_out_send_channel, mut ctrbc_out_recv_channel) = channel(10000);

    // Start Cachin-Tessaro RBC protocol. The exit handle it returns is kept in
    // `exit_handles`, which the caller owns.
    let mut exit_handles = Vec::new();
    exit_handles.push(ctrbc::Context::spawn(
        config,
        ctrbc_req_recv_channel,
        ctrbc_out_send_channel,
        false,
    )?);

    // `while let Some(..)` rather than a `loop`: once the module drops its
    // output sender, `recv` returns `None` forever, and a bare loop would spin
    // on it instead of finishing.
    tokio::spawn(async move {
        while let Some(msg) = ctrbc_out_recv_channel.recv().await {
            // Execute handling logic for the received message from the channel
            log::debug!("Received message from CTRBC channel {:?}", msg);
            // self.process_ctrbc_event(ctrbc_msg.1, ctrbc_msg.0, ctrbc_msg.2).await;
        }
        log::info!("CTRBC output channel closed, stopping the output listener");
    });

    ctrbc_req_send_channel
        .send(Vec::new())
        .await
        .map_err(|_| anyhow!("CTRBC stopped before the initial request was sent"))?;

    Ok(ProtocolHandles {
        req_send: ctrbc_req_send_channel,
        exit_handles,
    })
}

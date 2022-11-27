use std::{env, net::SocketAddrV4};

use rumqttc::{Client, MqttOptions};

fn main() -> anyhow::Result<()> {
    let mut args = env::args();
    let _bin_name = args.next().unwrap();

    let broker_addr: SocketAddrV4 = args
        .next()
        .expect("first arg should be broker addr")
        .parse()?;

    let mqttoptions = MqttOptions::new("script1", broker_addr.ip().to_string(), broker_addr.port());
    mqttoptions.set_keep_alive(Duration::from_secs(5));

    let (mut client, mut connection) = Client::new(mqttoptions, 1024);

    Ok(())
}

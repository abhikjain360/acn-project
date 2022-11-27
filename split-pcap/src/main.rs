use std::{collections::HashMap, env, fs::File, io::BufWriter};

use etherparse::{InternetSlice, SlicedPacket};
use pcap::Capture;
use pcap_file::PcapWriter;

fn main() -> anyhow::Result<()> {
    let mut args = env::args();
    args.next().unwrap();

    let pcap_file_path = args.next().expect("pass in file name");
    let mut pcap = Capture::from_file(pcap_file_path)?;

    let mut map = HashMap::new();
    loop {
        let packet = match pcap.next_packet() {
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(e.into()),
            Ok(v) => v,
        };
        let ts = packet.header.ts;
        let parsed_packet = SlicedPacket::from_ip(&packet.data[16..])?;
        // let parsed_packet = SlicedPacket::from_ethernet(packet.data)?;

        let (src, dst) = match parsed_packet.ip {
            None | Some(InternetSlice::Ipv6(_, _)) => continue,
            Some(InternetSlice::Ipv4(header, _ext)) => {
                (header.source_addr(), header.destination_addr())
            }
        };

        match map.get_mut(&(src, dst)) {
            None => {
                let file = File::create(format!("{src}-{dst}.pcap"))?;
                let mut capture_file = PcapWriter::new(BufWriter::new(file))?;
                capture_file.write(
                    ts.tv_usec as u32,
                    ts.tv_usec as u32 * 1000,
                    packet.data,
                    packet.data.len() as u32,
                )?;
                map.insert((src, dst), capture_file);
            }
            Some(capture_file) => {
                capture_file.write(
                    ts.tv_usec as u32,
                    ts.tv_usec as u32 * 1000,
                    packet.data,
                    packet.data.len() as u32,
                )?;
            }
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}

use std::{
    env::args,
    thread::sleep,
    time::{Duration, SystemTime},
    net::TcpStream,
};

use etherparse::SlicedPacket;

fn send_right(stream: &mut TcpStream, data: &[u8]) -> anyhow::Result<()> {
    let paarsed_packet = SlicedPacket::from_ethernet(data)?;


    todo!();


   #[allow(unreachable_code)]
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let mut args = args();
    args.next().unwrap();
    let file_name = args
        .next()
        .expect("1st argument should be a valid pcap file path");

    let mut pcap_file = pcap::Capture::from_file(file_name).unwrap();

    let mut timeout = SystemTime::now() + Duration::from_secs(5);
    let packet1 = pcap_file.next_packet().unwrap();
    let mut prev = packet1.header.ts;

    let stream = TcpStream::connect(([127, 0, 0, 1], 1883).into())?;

    capture.sendpacket(packet1.data).unwrap();
    let mut last_sent = SystemTime::now();

    let mut i: u128 = 0;


    while let Ok(packet) = pcap_file.next_packet() {
        let curts = packet.header.ts;
        let mut sd = curts.tv_sec - prev.tv_sec;
        let ud = if sd == 0 {
            curts.tv_usec - prev.tv_usec
        } else if curts.tv_usec > prev.tv_usec {
            curts.tv_usec - prev.tv_usec
        } else {
            sd -= 1;
            prev.tv_usec - curts.tv_usec
        };
        if sd > 0 || (sd == 0 && ud > 0) {
            let dur = Duration::from_secs(sd as u64) + Duration::from_micros(ud as u64);
            // print!("sd {sd:10} ud {ud:10} {dur:10?}");
            let new_time = last_sent + dur;
            let now = SystemTime::now();
            if new_time > now {
                let d = new_time.duration_since(now).unwrap();
                // println!("{:15} sleeping for {:?}",i, d);
                sleep(d);
            }
        }
        capture.sendpacket(packet.data).unwrap();
        last_sent = SystemTime::now();
        prev = curts;
        println!("sent {}", i);
        i = i.wrapping_add(1);

        let now = SystemTime::now();
        if timeout <= now {
            println!("{:#?}", capture.stats().unwrap());
            timeout = now + Duration::from_secs(5);
        }
    }

    Ok(())
}

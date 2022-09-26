use std::collections::VecDeque;

use anyhow::anyhow;
use bytes::BytesMut;
use etherparse::{InternetSlice, SlicedPacket};
use mqttbytes::v4::{Packet, SubscribeReasonCode};
use pcap::{Capture, Device};
use serde::Serialize;

#[derive(Debug, Default, Serialize)]
struct HeadersInfo {
    packet_len: usize,
    ip_len: u16,
    ip_df: bool,
    ip_mf: bool,
    ip_ttl: u8,
    tcp_len: usize,
    tcp_pdu_size: u8,
    tcp_ack: bool,
    tcp_cwr: bool,
    tcp_ece: bool,
    tcp_fin: bool,
    tcp_ns: bool,
    tcp_push: bool,
    tcp_reset: bool,
    tcp_syn: bool,
    tcp_urg: bool,
    tcp_src_port: u16,
    tcp_dst_port: u16,
    tcp_tdelta: i64,
    tcp_l20_avg: i64,
    mqtt_len: usize,
    mqtt_topic_len: usize,
    mqtt_msg_type: u8,
    mqtt_qos_lvl: u8,
}

fn main() -> anyhow::Result<()> {
    let mut localhost_device = None;
    for device in Device::list()? {
        if device.name == "lo" {
            localhost_device = Some(device);
            break;
        }
    }

    let device = localhost_device.ok_or(anyhow!("no lookup device"))?;
    let mut capture = Capture::from_device(device)?.timeout(1).open()?;

    let agent = ureq::agent();

    println!("starting capture");

    let mut packet = match capture.next_packet() {
        Ok(packet) => packet,
        Err(e) => {
            println!("{e}");
            return Ok(());
        }
    };

    let mut ts = packet.header.ts;
    let mut prev_ts = ts.tv_sec * 1_000_000 + ts.tv_usec;

    let mut tcp_l20_avg = 0;
    let mut l20_diffs = VecDeque::with_capacity(20);
    l20_diffs.push_back(0);

    loop {
        let mut info = HeadersInfo::default();
        info.packet_len = packet.data.len();

        let parsed_packet = SlicedPacket::from_ip(&packet.data[16..])?;

        match parsed_packet.ip {
            Some(InternetSlice::Ipv4(header, _)) => {
                info.ip_len = header.total_len();
                info.ip_df = header.dont_fragment();
                info.ip_mf = header.more_fragments();
                info.ip_ttl = header.ttl();
            }
            _ => {
                packet = match capture.next_packet() {
                    Err(pcap::Error::NoMorePackets) => break,
                    v => v?,
                };

                continue;
            }
        };

        let ts2 = packet.header.ts;
        ts = ts2;
        let curr_ts = ts.tv_sec * 1_000_000 + ts.tv_usec;
        let diff = curr_ts - prev_ts;

        let len = l20_diffs.len() as i64;
        if len < 20 {
            tcp_l20_avg = (tcp_l20_avg * len + diff) / len;
        } else {
            tcp_l20_avg = (tcp_l20_avg * 20 - l20_diffs.pop_front().unwrap() + diff) / 20;
        }

        l20_diffs.push_back(diff);
        prev_ts = curr_ts;

        match parsed_packet.transport {
            Some(etherparse::TransportSlice::Tcp(header))
                if header.source_port() != 8000 && header.destination_port() != 8000 =>
            {
                info.tcp_len = header.slice().len();
                info.tcp_pdu_size = header.data_offset();
                info.tcp_ack = header.ack();
                info.tcp_cwr = header.cwr();
                info.tcp_ece = header.ece();
                info.tcp_fin = header.fin();
                info.tcp_ns = header.ns();
                info.tcp_push = header.psh();
                info.tcp_reset = header.rst();
                info.tcp_syn = header.syn();
                info.tcp_urg = header.urg();
                info.tcp_src_port = header.source_port();
                info.tcp_dst_port = header.destination_port();
                info.tcp_tdelta = diff;
                info.tcp_l20_avg = tcp_l20_avg;
            }
            _ => {
                packet = match capture.next_packet() {
                    Err(pcap::Error::NoMorePackets) => break,
                    v => v?,
                };

                continue;
            }
        };

        let mqtt_packet =
            match mqttbytes::v4::read(&mut BytesMut::from(parsed_packet.payload), 1 << 30) {
                Ok(p) => p,
                Err(_) => {
                    packet = match capture.next_packet() {
                        Err(pcap::Error::NoMorePackets) => break,
                        v => v?,
                    };

                    continue;
                }
            };

        match mqtt_packet {
            Packet::Connect(conn) => {
                info.mqtt_len = conn.len();
                info.mqtt_topic_len = 0;
                info.mqtt_msg_type = 1;
                info.mqtt_qos_lvl = 0;
            }
            Packet::ConnAck(_) => {
                info.mqtt_len = 2;
                info.mqtt_topic_len = 0;
                info.mqtt_msg_type = 2;
                info.mqtt_qos_lvl = 0;
            }
            Packet::Publish(publish) => {
                info.mqtt_len = publish.len();
                info.mqtt_topic_len = publish.topic.len();
                info.mqtt_msg_type = 3;
                info.mqtt_qos_lvl = publish.qos as u8;
            }
            Packet::PubAck(_) => {
                info.mqtt_len = 2;
                info.mqtt_topic_len = 0;
                info.mqtt_msg_type = 4;
                info.mqtt_qos_lvl = 0;
            }
            Packet::PubRec(_) => {
                info.mqtt_len = 2;
                info.mqtt_topic_len = 0;
                info.mqtt_msg_type = 5;
                info.mqtt_qos_lvl = 0;
            }
            Packet::PubRel(_) => {
                info.mqtt_len = 2;
                info.mqtt_topic_len = 0;
                info.mqtt_msg_type = 6;
                info.mqtt_qos_lvl = 0;
            }
            Packet::PubComp(_) => {
                info.mqtt_len = 2;
                info.mqtt_topic_len = 0;
                info.mqtt_msg_type = 7;
                info.mqtt_qos_lvl = 0;
            }
            Packet::Subscribe(subscribe) => {
                let mqtt_len = subscribe.len();
                let filter = subscribe.filters.into_iter().next().unwrap();
                info.mqtt_len = mqtt_len;
                info.mqtt_topic_len = filter.path.len();
                info.mqtt_msg_type = 8;
                info.mqtt_qos_lvl = filter.qos as u8;
            }
            Packet::SubAck(ack) => {
                let mqtt_len = 2 + ack.return_codes.len();
                let filter = ack.return_codes.into_iter().next().unwrap();
                let mqtt_qos_lvl = match filter {
                    SubscribeReasonCode::Success(qos) => qos as u8,
                    _ => 0,
                };
                info.mqtt_len = mqtt_len;
                info.mqtt_topic_len = 0;
                info.mqtt_msg_type = 9;
                info.mqtt_qos_lvl = mqtt_qos_lvl;
            }
            Packet::Unsubscribe(ubsub) => {
                let mqtt_len = 2 + ubsub.topics.iter().map(|s| s.len() + 2).sum::<usize>();
                let filter = ubsub.topics.into_iter().next().unwrap();
                info.mqtt_len = mqtt_len;
                info.mqtt_topic_len = filter.len();
                info.mqtt_msg_type = 10;
                info.mqtt_qos_lvl = 0;
            }
            Packet::UnsubAck(_) => {
                info.mqtt_len = 2;
                info.mqtt_topic_len = 0;
                info.mqtt_msg_type = 11;
                info.mqtt_qos_lvl = 0;
            }
            Packet::PingReq => {
                info.mqtt_len = 0;
                info.mqtt_topic_len = 0;
                info.mqtt_msg_type = 12;
                info.mqtt_qos_lvl = 0;
            }
            Packet::PingResp => {
                info.mqtt_len = 0;
                info.mqtt_topic_len = 0;
                info.mqtt_msg_type = 13;
                info.mqtt_qos_lvl = 0;
            }
            Packet::Disconnect => {
                info.mqtt_len = 0;
                info.mqtt_topic_len = 0;
                info.mqtt_msg_type = 14;
                info.mqtt_qos_lvl = 0;
            }
        };

        agent.get("localhost:8000").send_string(&serde_json::to_string(&info)?)?;

        packet = match capture.next_packet() {
            Ok(packet) => packet,
            Err(e) => {
                println!("{e}");
                break;
            }
        };
    }

    Ok(())
}

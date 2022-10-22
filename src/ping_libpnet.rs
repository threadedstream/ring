extern crate pnet;

use pnet::packet::icmp::{echo_request::MutableEchoRequestPacket, IcmpTypes};
use pnet_datalink::{self, NetworkInterface};
use pnet_datalink::Channel::Ethernet;
use std::net::{IpAddr, Ipv4Addr};

use std::env;
use pnet::packet;
use pnet::packet::ip::IpNextHeaderProtocols::Icmp;
use pnet_transport::{icmp_packet_iter, transport_channel, TransportChannelType};

pub fn shoot_packets() {
    let (mut tx, mut rx) = match transport_channel(1500, TransportChannelType::Layer4(pnet_transport::TransportProtocol::Ipv4(Icmp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("panic when composing icmp transport channel: {}" , e),
    };
    let mut payload = [0u8; 64];
    let dst = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
    let mut recv = icmp_packet_iter(&mut rx);
    loop {
        let mut ping = MutableEchoRequestPacket::new(&mut payload).unwrap();
        ping.set_icmp_type(IcmpTypes::EchoRequest);
        ping.set_payload(b"hello");
        println!("Bytes send: {}", tx.send_to(ping, IpAddr::V4(dst)).unwrap());
        match recv.next() {
            Ok((pkt,addr)) => println!("{:#?} {}", pkt, addr),
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}
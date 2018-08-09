extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ethernet::EtherTypes::{Arp, Ipv4, Ipv6, Rarp, Vlan, WakeOnLan};
use pnet::packet::PrimitiveValues;
use pnet::packet::ethernet::EtherType;
use pnet::util::MacAddr;
use std::env;
use std::collections::HashMap;

struct PacketTracker {
    counter: HashMap<u16, u64>,
}

impl PacketTracker {
    fn new() -> PacketTracker {
        PacketTracker {
            counter: HashMap::new()
        }
    }

    fn inspect_packet(&mut self, packet: EthernetPacket) {
        println!("got packet: {:?}", packet);
        println!("got packet dest: {:?}", packet.get_destination());
        println!("got packet src : {:?}", packet.get_source());
        println!("got packet type: {:?}", packet.get_ethertype());
        let c = self.counter.entry(packet.get_ethertype().to_primitive_values().0).or_insert(0);
        *c += 1;
    //    println!("got packet size: {:?}", MutableEthernetPacket::packet_size(&packet));
    }

    fn pretty_out(&self) {
        for (k, v) in self.counter.iter() {
            let print_k = match EtherType(*k) {
                Arp => "Arp".to_string(),
                Rarp => "Rarp".to_string(),
                Vlan => "Vlan".to_string(),
                WakeOnLan => "WakeOnLan".to_string(),
                Ipv4 => "Ipv4".to_string(),
                Ipv6 => "Ipv6".to_string(),
                _ => format!("Unknown {}", k),
            };
            println!(" {:<15} : {} ", print_k, v)
        }
    }
}

fn mac_to_string(mac: Option<MacAddr>) -> String {
    match mac {
        Some(m) => m.to_string(),
        None => "Unknown mac address".to_string()
    }
}
fn print_my_options() {
    println!("Run me with a name of a network interface");
    println!("Here are your network interfaces");
    println!("Name:       MAC:");
    for i in datalink::interfaces().into_iter() {
        println!("{:<9} {:?}", i.name, mac_to_string(i.mac));
    };
}

// Invoke as echo <interface name>
fn main() {
    if env::args().len() < 2 {
        print_my_options();
    } else {
        doit();
    }
}

fn doit() {
    let interface_name = env::args().nth(1).unwrap_or("eth0".to_string());
    let interface_names_match =
        |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface_a = interfaces.into_iter()
                              .filter(interface_names_match)
                              .next();
    let interface = interface_a.unwrap();

    let mut pt = PacketTracker::new();

    // Create a new channel, dealing with layer 2 packets
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    let mut count = 0;
    loop {
        count += 1;
        if count > 30 {
            break
        }
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                pt.inspect_packet(packet);
            },
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
    println!("{:?}", pt.counter);
    pt.pretty_out();
}
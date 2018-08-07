extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::ethernet::EtherTypes::{Arp, Ipv4, Ipv6, Rarp, Vlan, WakeOnLan};
use pnet::packet::PrimitiveValues;
use pnet::packet::ethernet::EtherType;
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
            println!(" {} : {} ", print_k, v)
        }
    }
}


// Invoke as echo <interface name>
fn main() {
    let interface_name = env::args().nth(1).unwrap();
    let interface_names_match =
        |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
                              .filter(interface_names_match)
                              .next()
                              .unwrap();

    for i in datalink::interfaces().into_iter() {
        println!("{:?}", i);
    }

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

                // Constructs a single packet, the same length as the the one received,
                // using the provided closure. This allows the packet to be constructed
                // directly in the write buffer, without copying. If copying is not a
                // problem, you could also use send_to.
                //
                // The packet is sent once the closure has finished executing.
/*                tx.build_and_send(1, packet.packet().len(),
                    &mut |mut new_packet| {
                        //print!("HEllo packet send");
                        let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();

                        // Create a clone of the original packet
                        new_packet.clone_from(&packet);

                        // Switch the source and destination
                        new_packet.set_source(packet.get_destination());
                        new_packet.set_destination(packet.get_source());
                        inspect_packet(new_packet);
                });*/
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
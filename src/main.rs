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
use std::cmp::max;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;


const OLD_ETHERNET :u16 = 2047;

struct PacketTracker {
    counter: HashMap<u16, u64>,
    is_my_box: HashMap<bool, u64>,
    me: NetworkInterface,
    just_me: bool,
}

impl PacketTracker {
    fn new(iface: NetworkInterface, jm: bool) -> PacketTracker {
        let mut pt = PacketTracker {
            counter: HashMap::new(),
            is_my_box: HashMap::new(),
            me: iface,
            just_me: jm,
        };
        pt.is_my_box.entry(true).or_insert(0);
        pt.is_my_box.entry(false).or_insert(0);
        pt
    }

    fn inspect_packet(&mut self, packet: EthernetPacket) {
        //println!("got packet: {:?}", packet);
        //println!("got packet dest: {:?}", packet.get_destination());
        //println!("got packet src : {:?}", packet.get_source());
        //println!("got packet type: {:?}", packet.get_ethertype());
        let packet_is_for_me = packet.get_source() == self.me.mac.unwrap() || packet.get_destination() == self.me.mac.unwrap();
        if self.just_me && !packet_is_for_me {
            return
        }
        let c = self.is_my_box.entry(packet_is_for_me).or_insert(0);
        *c += 1;
        let v = max(OLD_ETHERNET, packet.get_ethertype().to_primitive_values().0);
        let c = self.counter.entry(v).or_insert(0);
        *c += 1;
    //    println!("got packet size: {:?}", MutableEthernetPacket::packet_size(&packet));
    }

    fn pretty_out(&mut self, start_time: &SystemTime) {
        println!("Time from {:?} ", start_time);
        for (k, v) in self.counter.iter() {
            let print_k = match EtherType(*k) {
                EtherType(OLD_ETHERNET) => "Pre ether2".to_string(),
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
        if !self.just_me {
            println!(" packets for me     : {:?} ", self.is_my_box[&true]);
            println!(" packets for others : {:?} ", self.is_my_box[&false]);
        }
        self.counter.clear();
        self.is_my_box.clear();
        self.is_my_box.entry(true).or_insert(0);
        self.is_my_box.entry(false).or_insert(0);
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
    println!("Name:      MAC:");
    for i in datalink::interfaces().into_iter() {
        println!("{:<9} {:?}", i.name, mac_to_string(i.mac));
    };
}

// Invoke as echo <interface name>
fn main() {
    match env::args().nth(1) {
        None => print_my_options(),
        Some(interface_name) => {
            let just_me = env::args().nth(2).unwrap_or("false".to_string());
            doit(&interface_name, just_me.to_lowercase() == "true")
        }
    }
}

fn doit(interface_name : &String, just_me: bool) {
    println!("running packet monitor.{}", just_me);
    if just_me {
        println!("Just analysing packets for this box");
    } else {
        println!("Analysing all packets seen on network");
    }
    let interface_names_match =
        |iface: &NetworkInterface| iface.name == *interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface_a = interfaces.into_iter()
                              .filter(interface_names_match)
                              .next();
    let interface = interface_a.unwrap();

    let mut pt = PacketTracker::new(interface.clone(), just_me);

    // Create a new channel, dealing with layer 2 packets
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    //print_thread(&pt);
    //let mut count = 0;
    let mut start_counting_time = SystemTime::now();
    loop {
        //count += 1;
        /*if count > 30 {
            break
        }*/
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
        if start_counting_time + Duration::new(5, 0) < SystemTime::now() {
            pt.pretty_out(&start_counting_time);
            start_counting_time = SystemTime::now()
        }
    }
}

/*fn print_thread(pt: &PacketTracker) {
    thread::spawn(|| {
        loop {
            thread::sleep(Duration::from_millis(1000 * 5));
            pt.pretty_out();
        }
    });
}*/
use serde_json::{Value, Map};
use crate::routes::*;
use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub enum Action {
    ADD,
    REMOVE,
}

fn extract_route(map: serde_json::Map<std::string::String, serde_json::Value>) -> Option<Route> {
    match map.get("udpAddrs") {
        Some(addrs) => {
            println!("got an addrs struct");
            for addr in addrs.as_array().unwrap() {
                // Make a new route based on our udp addr
                //let dest_ip = addr.get("ip").unwrap().as_str().unwrap();
                let dest_ip = addr.get("ip").unwrap().as_str().unwrap();
                println!("{}", dest_ip);
                return Some(Route {
                    destination: dest_ip.parse().unwrap(), // Parse the string as an ip
                    netmask: Ipv4Addr::new(255, 255, 255, 255),
                    gateway: Ipv4Addr::new(192, 168, 1, 254), // BAD
                    interface: 15, //BAAAAAD
                    metric: 300, //BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD
                });
            }
        },
        None => println!("no addrs"),
    }
    None
}

pub fn parse_message(message_map: Map<String, Value>) -> Option<(Action, Route)> {

    match message_map.get("msg") {
        Some(msg) => {
            print!("we got a handshake message -- ");
            match msg.as_str() {
                Some("Handshake message sent") => {
                    if let Some(route) = extract_route(message_map) {
                        return Some((Action::ADD, route));
                    }
                }
                Some("Close tunnel received, tearing down.") => {
                    if let Some(route) = extract_route(message_map) {
                        return Some((Action::REMOVE, route));
                    }
                }
                Some(msg) => {
                    println!("Some other message: {}", msg)
                }
                None => {
                    panic!("msg.as_str() broke, should never happen")
                }
            }
            
        }
        None => {
            println!("No message, not interested");
        }
    }
    None
}
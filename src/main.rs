#[macro_use(quick_error)] extern crate quick_error;
extern crate dns_parser;
extern crate byteorder;
extern crate itertools;

use byteorder::BigEndian;
use std::net::UdpSocket;
use std::net::{ToSocketAddrs, SocketAddr};
use dns_parser::Packet;

mod dns;

fn print_header(header: &dns_parser::Header) {
    println!("Packet {:x}:", header.id);
    if header.query {print!("\tQuery")} else {print!("\tResponse")}
    println!(" for {:?}", header.opcode);
    print!("\tFlags");
    if header.authoritative { print!(" authoritative") }
    if header.truncated { print!(" truncated") }
    if header.recursion_desired { print!(" recurse_desired") }
    if header.recursion_available { print!(" recurse_avail") }
    if header.authenticated_data { print!(" auth") }
    if header.checking_disabled { print!(" nocheck") }
    print!("\n");
    if header.response_code != dns_parser::ResponseCode::NoError {
        println!("\t{:?}", header.response_code);
    }
}

fn print_packet(pkt: &Packet) {
    print_header(&pkt.header);

    if pkt.questions.len() != 0 { println!("\tQuestions:"); }
    for q in pkt.questions.iter() {
        println!("\t\t{:?} {:?} {}", q.qclass, q.qtype, q.qname);
    }

    if pkt.answers.len() != 0 { println!("\tAnswers:"); }
    for a in pkt.answers.iter() {
        println!("\t\t{:?}", a);
    }

    if pkt.nameservers.len() != 0 { println!("\tNameservers:"); }
    for ns in pkt.nameservers.iter() {
        println!("\t\t{:?}", ns);
    }

    if pkt.additional.len() != 0 {println!("\tAdditional RRs:"); }
    for rr in pkt.additional.iter() {
        println!("\t\t{:?}", rr);
    }

    //TODO:  This formatting probably needs work
    if let Some(ref opt) = pkt.opt {
        println!("\tRFC 6891 OPT Data:");
        println!("\t\tEDNS v{}; UDP Max Size {}", opt.version , opt.udp);
        println!("\t\tFlags {}", opt.flags);
        if let dns_parser::RRData::Unknown(ref data) = opt.data {
            if data.len() > 0 {
                println!("\t\t{:?}", data);
            }
        }
        else { println!("\t\t{:?}", opt.data); }
    }
}

fn handle_packet(buf: &[u8], sz: usize, srcaddr: SocketAddr) {
    let pkt = match Packet::parse(&buf) {
        Ok(p) => p,
        Err(e) => {println!("Error parsing packet: {}", e); return;}
    };
    print_packet(&pkt);
}

fn main() {
    //TODO: Config
    let upstream = "8.8.8.8:53".to_socket_addrs();
    let socket = match UdpSocket::bind("0.0.0.0:53") {
        Ok(s) => s,
        Err(e) => panic!("Failed to bind: {}", e)
    };
    let mut buf = [0 as u8; 2048];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((amt, src)) => {
                match Packet::parse(&buf) {
                    Ok(p) => {
                        print_packet(&p);

                    }
                    Err(e) => {
                        println!("packet (source {}) parse error: {}", src, e);
                        //FIXME: Try and include a packet ID for diagnostics
                    }
                }
            },
            Err(e) => println!("recv error: {}", e)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

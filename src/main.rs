extern crate dns_parser;

use std::net::UdpSocket;
use std::net::SocketAddr;
use dns_parser::Packet;

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

fn print_questions(qvec: &Vec<dns_parser::Question>) {
    println!("\tQuestions:");
    for q in qvec {
        println!("\t\t{:?} {:?} {}", q.qclass, q.qtype, q.qname);
    }
}

fn print_packet(pkt: &Packet) {
    print_header(&pkt.header);
    print_questions(&pkt.questions);
}

fn handle_packet(buf: &[u8], sz: usize, srcaddr: SocketAddr) {
    let pkt = match Packet::parse(&buf) {
        Ok(p) => p,
        Err(e) => {println!("Error parsing packet: {}", e); return;}
    };
    print_packet(&pkt);
}

fn main() {
    let socket = match UdpSocket::bind("0.0.0.0:53") {
        Ok(s) => s,
        Err(e) => panic!("Failed to bind: {}", e)
    };
    let mut buf = [0 as u8; 2048];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((amt, src)) => handle_packet(&buf, amt, src),
            Err(e) => println!("Error recv: {}", e)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

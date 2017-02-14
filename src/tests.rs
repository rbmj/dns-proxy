use dns;
use dns::{Message, Question, Type, ResourceRecord, Class};
use dns_parser;
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

#[test]
fn serialize_query() {
    let mut query = Message::new_query(0x1337);
    query.add_question(Question::new_str("www.google.com", Class::IN, Type::A).unwrap());
    print!("{}", query);
    let buf = query.serialize().unwrap();
    let pkt = Packet::parse(&buf[..]).unwrap();
    print_packet(&pkt);
}
#[test]
fn serialize_response() {
    let mut response = Message::new_response(0xfeed);
    response.add_answer(ResourceRecord::new_str
        ::<dns::A>("www.google.com", Class::IN, "8.8.8.8").unwrap());
    print!("{}", response);
    let buf = response.serialize().unwrap();
    println!("");
    let pkt = Packet::parse(&buf[..]).unwrap();
    print_header(&pkt.header);
    let newresp = Message::from_packet(&pkt).unwrap();
    print!("{}", newresp);
}

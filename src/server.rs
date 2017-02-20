use std;
use rand::random;
use dns;
use Action;
use filter::Filter;
use std::net::{UdpSocket, ToSocketAddrs, SocketAddr, SocketAddrV4, Ipv4Addr};

fn ipv4null() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0))
}

// instead of a big array, to scale properly you'd really want
// a large (say 200,000 element) doubly-keyed linked hash table
// acting as a gigantic LRU cache that would allow lookups
// based both either the (origin, origin_id) tuple OR the
// (upstream, upstream_id) tuple.  This shouldn't be necessary
// at any but the largest load factors, however.

#[derive(Copy, Clone)]
struct ConnectionData {
    origin: SocketAddr,
    origin_id: u16,
    upstream: SocketAddr,
    upstream_id: u16
}

impl ConnectionData {
    pub fn new() -> Self {
        ConnectionData {
            origin: ipv4null(),
            origin_id: 0,
            upstream: ipv4null(),
            upstream_id: 0
        }
    }
}

pub struct Server {
    udpsock: UdpSocket,
    udpbuf: [u8; 4096],
    udpseq: u16,
    upstream: std::vec::Vec<SocketAddr>,
    requests: std::vec::Vec<ConnectionData>, //65536 elements after init
    filter: Filter
}

impl Server {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        let mut v = std::vec::Vec::<ConnectionData>::with_capacity(65536);
        for _ in 0..65536 {
            v.push(ConnectionData::new());
        }
        Ok(Server{
            udpsock: UdpSocket::bind(addr)?,
            udpbuf: [0; 4096],
            udpseq: random::<u16>(),
            upstream: "8.8.8.8:53".to_socket_addrs().unwrap().collect(),
            requests: v,
            filter: Filter::new()
        })
    }
    fn udpseq_advance(&mut self) -> u16 {
        self.udpseq = self.udpseq.wrapping_add(1);
        if self.udpseq < 1024 {
            self.udpseq = 1024;
        }
        self.udpseq
    }
    fn select_upstream(&self) -> &SocketAddr {
        self.upstream.get(random::<usize>() % self.upstream.len()).unwrap()
    }
    fn send_message(&mut self, msg: &dns::Message, addr: SocketAddr) {
        match msg.serialize() {
            Ok(m) => if let Err(e) = self.udpsock.send_to(&m[..], addr) {
                //send error: why?
                //TODO: log
            },
            Err(e) => {
                //serialization error
            }
        }
    }
    fn forward_request(&mut self, req: &dns::Message, origin: SocketAddr,
                       fwdmsg: &dns::Message, upstream: SocketAddr)
    {
        let id = fwdmsg.id();
        // Store for return round
        {
            let data = self.requests.get_mut(id as usize).unwrap();
            data.origin = origin;
            data.origin_id = req.id();
            data.upstream = upstream;
            data.upstream_id = id;
        }
        self.send_message(fwdmsg, upstream);
    }
    fn process_request(&mut self, msg: &mut dns::Message, origin: SocketAddr) {
        match self.filter.filter_request(msg, origin) {
            Action::Pass => {
                let mut fwd = msg.clone();
                fwd.set_id(self.udpseq_advance());
                let upstream = self.select_upstream().clone();
                self.forward_request(msg, origin, &fwd, upstream);
            },
            Action::PassMangled(mut newm) => {
                newm.set_id(self.udpseq_advance());
                let upstream = self.select_upstream().clone();
                self.forward_request(&newm, origin, &newm, upstream);
            }
            Action::SendServFail => {
                let mut resp = dns::Message::from_header(msg);
                resp.set_recursion_available(true);
                resp.set_response_code(dns::ResponseCode::ServFail);
                self.send_message(&resp, origin);
            },
            Action::SendNxDomain => {
                let mut resp = dns::Message::from_header(msg);
                resp.set_recursion_available(true);
                resp.set_response_code(dns::ResponseCode::NxDomain);
                self.send_message(&resp, origin);
            },
            Action::SendRefused => {
                let mut resp = dns::Message::from_header(msg);
                resp.set_recursion_available(true);
                resp.set_response_code(dns::ResponseCode::Refused);
                self.send_message(&resp, origin);
            },
            Action::Nop => {},
            Action::SendResponse(newm) => {
                self.send_message(&newm, origin);
            },
            Action::MessageTo(newm, addr) => {
                self.forward_request(msg, origin, &newm, addr);
            }
        }
    }
    fn process_response(&mut self, msg: &mut dns::Message, upstream: SocketAddr) {
        let data : ConnectionData;
        {
            let _data = self.requests.get_mut(msg.id() as usize).unwrap();
            data = *_data;
            *_data = ConnectionData::new();
        }
        if upstream != data.upstream || msg.id() != data.upstream_id {
            //potential reflection attack
            //TODO: log
            return;
        }
        if data.origin == ipv4null() {
            //bogus packet - drop
            return;
        }
        match self.filter.filter_response(msg, data.origin, data.origin_id,
                                          data.upstream)
        {
            Action::Pass => {
                msg.set_id(data.origin_id);
                self.send_message(msg, data.origin);
            },
            Action::PassMangled(mut newm) => {
                newm.set_id(data.origin_id);
                self.send_message(&newm, data.origin);
            }
            Action::SendServFail => {
                let mut resp = dns::Message::from_header(msg);
                resp.set_response_code(dns::ResponseCode::ServFail);
                self.send_message(&resp, data.origin);
            },
            Action::SendNxDomain => {
                let mut resp = dns::Message::from_header(msg);
                resp.set_response_code(dns::ResponseCode::NxDomain);
                self.send_message(&resp, data.origin);
            },
            Action::SendRefused => {
                let mut resp = dns::Message::from_header(msg);
                resp.set_response_code(dns::ResponseCode::Refused);
                self.send_message(&resp, data.origin);
            },
            Action::Nop => {},
            Action::SendResponse(mut newm) => {
                newm.set_id(data.origin_id);
                self.send_message(&newm, data.origin);
            },
            Action::MessageTo(newm, addr) => {
                let id = newm.id();
                {
                    let mut newdata =
                            self.requests.get_mut(id as usize).unwrap();
                    newdata.origin = data.origin;
                    newdata.origin_id = data.origin_id;
                    newdata.upstream = addr;
                    newdata.upstream_id = id;
                }
                self.send_message(&newm, addr);
            }
        }
    }
    fn process_message(&mut self, msg: &mut dns::Message, addr: SocketAddr) {
        println!("{}", msg);
        if msg.is_request() { 
            self.process_request(msg, addr)
        }
        else {
            self.process_response(msg, addr)
        }
    }
    pub fn serve_forever(&mut self) {
        loop {
            if let Ok((sz, addr)) = self.udpsock.recv_from(&mut self.udpbuf) {
                if let Ok(mut msg) = dns::Message::parse(&self.udpbuf) {
                    self.process_message(&mut msg, addr);
                }
                else {
                    //bad packet, try and send a coherent response
                    let mut id = 0 as u16;
                    if sz >= 2 {
                        id = ((self.udpbuf[0] as u16) << 8) | (self.udpbuf[1] as u16);
                    }
                    let msg = dns::Message::new_error(id, dns::ResponseCode::FormErr);
                    //and if this fails, we don't really care
                    if let Ok(m) = msg.serialize() {
                        self.udpsock.send_to(&m[..], addr).ok();
                    }
                }
            }
            else {
                //log recv failure
                println!("recv fail");
            }
        }
    }
}

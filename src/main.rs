extern crate dnis as dns;
extern crate rand;
extern crate lru_cache;

mod server;
mod filter;
use server::Server;
use dns::Message;
use std::net::SocketAddr;

pub enum Action {
    Pass,
    PassMangled(Message),
    SendServFail,
    SendNxDomain,
    SendRefused,
    Nop,
    SendResponse(Message),
    MessageTo(Message, SocketAddr)
}

#[cfg(not(test))]
fn main() {
    let mut s = Server::bind("0.0.0.0:53").unwrap();
    s.serve_forever();
}

#[cfg(test)]
mod tests;

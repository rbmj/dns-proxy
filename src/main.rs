#[macro_use(quick_error)] extern crate quick_error;
extern crate dns_parser;
extern crate byteorder;
extern crate itertools;
extern crate rand;
extern crate lru_cache;

mod dns;
mod server;
use server::Server;

#[cfg(not(test))]
fn main() {
    let mut s = Server::bind("0.0.0.0:53").unwrap();
    s.serve_forever();
}

#[cfg(test)]
mod tests;

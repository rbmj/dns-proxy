//! `Filter` Module Documentation
//! 
//! See the minimal example below for struct names and
//! function signatures.  See documentation on Action for
//! possible server actions to take on packet
//! 
//! ```
//! use std;
//! use std::net::SocketAddr;
//! 
//! use dns;
//! use Action;
//! use Action::*;
//! use dns::types::*;
//! use dns::Message;
//! 
//! struct Filter {
//!     //Fill with whatever state you wish to keep
//! }
//! 
//! impl Filter {
//!     pub fn new() -> Self {
//!         Filter{}
//!     }
//!     pub fn filter_request(&mut self, msg: &Messsage, origin: SocketAddr)
//!         -> Action
//!     {
//!         Pass
//!     }
//!     pub fn filter_response(&mut self, msg: &Message, origin: SocketAddr,
//!         origin_id: u16, upstream: SocketAddr) -> Action
//!     {
//!         Pass
//!     }
//! }
//! ```


use std;
use dns;
use lru_cache;

use std::net::SocketAddr;
use dns::Message;
use dns::types::*;
use Action;
use Action::*;

pub struct Filter {
    //state
}

impl Filter {
    pub fn new() -> Self {
        Filter{}
    }
    pub fn filter_request(&mut self, msg: &Message, origin: SocketAddr)
        -> Action
    {
        for q in msg.iter_questions() {
            if q.is::<TXT>() {
                return SendRefused
            }
        }
        Pass
    }
    pub fn filter_response(&mut self, msg: &Message, origin: SocketAddr,
        origin_id: u16, upstream: SocketAddr) -> Action
    {
        Pass
    }
}


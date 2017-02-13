use std::fmt;
use std::io::{Cursor, Write};
use byteorder::{BigEndian, WriteBytesExt};

use super::{Name, Error};
pub use dns_parser::{QueryType, QueryClass};
use dns_parser;

pub struct Question {
    pub name: Name,
    pub prefer_unicast: bool,
    pub qtype: QueryType,
    pub qclass: QueryClass
}

impl Question {
    pub fn to_string(&self) -> String {
        format!("{:?} {:?} {}", self.qclass, self.qtype, self.name)
    }
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error> 
        where Cursor<T> : Write
    {
        try!(self.name.serialize(cursor));
        try!(cursor.write_u16::<BigEndian>(self.qtype as u16));
        let mut class = self.qclass as u16;
        if self.prefer_unicast { class |= 0x8000u16; }
        try!(cursor.write_u16::<BigEndian>(class));
        Ok(())
    }
    pub fn from_packet(q: &dns_parser::Question) -> Result<Self, Error> {
        let n = Name::from_string(q.qname.to_string())?;
        Ok(Question{
            name: n,
            prefer_unicast: q.prefer_unicast,
            qtype: q.qtype,
            qclass: q.qclass
        })
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}


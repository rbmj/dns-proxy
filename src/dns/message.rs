use std::fmt;
use std::io::{Cursor, Write};
use byteorder::{BigEndian, WriteBytesExt};

use super::{Name, Question, ResourceRecord, OptRecord, Error};
use dns_parser;
pub use dns_parser::{Header, Packet};

pub struct Message {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    authority: Vec<ResourceRecord>,
    additional: Vec<ResourceRecord>,
    opt: Option<OptRecord>
}

pub fn serialize_header<T>(header: &Header, cursor: &mut Cursor<T>) -> Result<(), Error> 
    where Cursor<T> : Write
{
    let mut buf = [0u8; 12];
    header.write(&mut buf);
    try!(cursor.write_all(&buf));
    Ok(())
}

impl Message {
    pub fn from_packet<'a>(pkt: &Packet<'a>) -> Result<Self, Error> {
        try!(Self::sanity_check_pkt(pkt));
        let mut o = None;
        if let Some(ref opt) = pkt.opt {
            o = Some(OptRecord::from_packet(opt)?);
        }
        Ok(Message{
            header: pkt.header,
            questions: pkt.questions.iter().map(|q| Question::from_packet(q))
                .collect::<Result<Vec<_>, _>>()?,
            answers: pkt.answers.iter().map(|rr| ResourceRecord::from_packet(rr))
                .collect::<Result<Vec<_>, _>>()?,
            authority: pkt.nameservers.iter().map(|rr| ResourceRecord::from_packet(rr))
                .collect::<Result<Vec<_>, _>>()?,
            additional: pkt.additional.iter().map(|rr| ResourceRecord::from_packet(rr))
                .collect::<Result<Vec<_>, _>>()?,
            opt: o
        })
    }
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let mut curs = Cursor::new(Vec::<u8>::new()); //FIXME: estimate size?
        try!(serialize_header(&self.header, &mut curs));
        for q in self.questions.iter() { try!(q.serialize(&mut curs)); }
        for a in self.answers.iter() { try!(a.serialize(&mut curs)); }
        for a in self.authority.iter() { try!(a.serialize(&mut curs)); }
        for a in self.additional.iter() { try!(a.serialize(&mut curs)); }
        if let Some(ref o) = self.opt { try!(o.serialize(&mut curs)); }
        return Ok(curs.into_inner());
    }
    fn sanity_check_pkt(pkt: &Packet) -> Result<(), Error> {
        if pkt.questions.len() != pkt.header.questions as usize {
            return Err(Error::ParserError(dns_parser::Error::WrongState));
        }
        if pkt.answers.len() != pkt.header.answers as usize {
            return Err(Error::ParserError(dns_parser::Error::WrongState));
        }
        if pkt.nameservers.len() != pkt.header.nameservers as usize {
            return Err(Error::ParserError(dns_parser::Error::WrongState));
        }
        let mut numaddl = pkt.additional.len();
        if pkt.opt.is_some() {
            numaddl += 1;
        }
        if numaddl != pkt.header.additional as usize {
            return Err(Error::ParserError(dns_parser::Error::WrongState));
        }
        Ok(())
    }
}


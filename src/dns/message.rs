use std::fmt;
use std::io::{Cursor, Write};
//use std::slice::SliceIndex;
use byteorder::{BigEndian, WriteBytesExt};

use super::{Name, Question, ResourceRecord, OptRecord, Error};
use dns_parser;

pub use dns_parser::{Packet, Opcode, ResponseCode};
pub use std::slice::{Iter, IterMut};

#[derive(Clone)]
pub struct Header {
    pub id: u16,
    pub query: bool,
    pub opcode: Opcode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub response_code: ResponseCode
}

impl Header {
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T> : Write
    {
        cursor.write_u16::<BigEndian>(self.id)?;
        let mut flags = 0u16;
        if !self.query { flags |= (1 << 15); }
        flags |= match self.opcode {
            Opcode::StandardQuery => 0,
            Opcode::InverseQuery => 1,
            Opcode::ServerStatusRequest => 2,
            _ => 3 //FIXME
        } << 11;
        if self.authoritative { flags |= (1 << 10); }
        if self.truncated { flags |= (1 << 9); }
        if self.recursion_desired { flags |= (1 << 8); }
        if self.recursion_available {flags |= (1 << 7); }
        flags |= match self.response_code {
            ResponseCode::NoError => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServerFailure => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImplemented => 4,
            ResponseCode::Refused => 5,
            _ => 6 //FIXME
        };
        cursor.write_u16::<BigEndian>(flags)?;
        Ok(())
    }
    pub fn from_packet(header: &dns_parser::Header) -> Self {
        Header {
            id: header.id,
            query: header.query,
            opcode: header.opcode,
            authoritative: header.authoritative,
            truncated: header.truncated,
            recursion_desired: header.recursion_desired,
            recursion_available: header.recursion_available,
            authenticated_data: header.authenticated_data,
            checking_disabled: header.checking_disabled,
            response_code: header.response_code
        }
    }
}

#[derive(Clone)]
pub struct Message {
    head: Header,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    authority: Vec<ResourceRecord>,
    additional: Vec<ResourceRecord>,
    opt: Option<OptRecord>
}

impl Message {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let pkt = Packet::parse(data)?;
        Self::from_packet(&pkt)
    }
    pub fn from_header(h: &Header) -> Self {
        Message {
            head: Header {
                id: h.id,
                query: h.query,
                opcode: h.opcode,
                authoritative: h.authoritative,
                truncated: h.truncated,
                recursion_desired: h.recursion_desired,
                recursion_available: h.recursion_available,
                authenticated_data: h.authenticated_data,
                checking_disabled: h.checking_disabled,
                response_code: h.response_code,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            opt: None
        }
    }
    //TODO: Flag system
    pub fn new_query(id: u16) -> Self {
        Message {
            head: Header {
                id: id,
                query: true,
                opcode: Opcode::StandardQuery,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: false,
                authenticated_data: false,
                checking_disabled: false,
                response_code: ResponseCode::NoError,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            opt: None
        }
    }
    pub fn new_error(id: u16, rc: ResponseCode) -> Self {
        Message {
            head: Header {
                id: id,
                query:false,
                opcode: Opcode::StandardQuery,
                authoritative: false,
                truncated: false,
                recursion_desired: false,
                recursion_available: true,
                authenticated_data: false,
                checking_disabled: false,
                response_code: rc
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            opt: None
        }
    }
    pub fn new_response(id: u16) -> Self {
        Message {
            head: Header {
                id: id,
                query: true,
                opcode: Opcode::StandardQuery,
                authoritative: false,
                truncated: false,
                recursion_desired: false,
                recursion_available: true,
                authenticated_data: false,
                checking_disabled: false,
                response_code: ResponseCode::NoError,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            opt: None
        }
    }
    pub fn from_packet<'a>(pkt: &Packet<'a>) -> Result<Self, Error> {
        try!(Self::sanity_check_pkt(pkt));
        let mut o = None;
        if let Some(ref opt) = pkt.opt {
            o = Some(OptRecord::from_packet(opt)?);
        }
        Ok(Message{
            head: Header::from_packet(&pkt.header),
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
    pub fn header(&self) -> &Header {
        &self.head
    }
    pub fn id(&self) -> u16 {
        self.head.id
    }
    pub fn set_id(&mut self, id: u16) {
        self.head.id = id
    }
    pub fn is_request(&self) -> bool {
        self.head.query
    }
    pub fn is_response(&self) -> bool {
        !self.head.query
    }
    pub fn iter_questions(&self) -> Iter<Question> {
        self.questions.iter()
    }
    pub fn iter_mut_questions(&mut self) -> IterMut<Question> {
        self.questions.iter_mut()
    }
    pub fn iter_answers(&self) -> Iter<ResourceRecord> {
        self.answers.iter()
    }
    pub fn iter_mut_answers(&mut self) -> IterMut<ResourceRecord> {
        self.answers.iter_mut()
    }
    pub fn iter_authoritiy(&self) -> Iter<ResourceRecord> {
        self.authority.iter()
    }
    pub fn iter_mut_authority(&mut self) -> IterMut<ResourceRecord> {
        self.authority.iter_mut()
    }
    pub fn iter_additional(&self) -> Iter<ResourceRecord> {
        self.additional.iter()
    }
    pub fn iter_mut_additional(&mut self) -> IterMut<ResourceRecord> {
        self.additional.iter_mut()
    }
    //Blocked on update to 1.15
    /*
    pub fn get_question<I: SliceIndex<Question>>(&self, index: I) -> Option<&I::Output> {
        self.questions.get(index)
    }
    pub fn get_mut_question<I: SliceIndex<Question>>(&mut self, index: I) -> Option<&I::Output> {
        self.questions.get_mut(index)
    }
    pub fn get_answer<I: SliceIndex<ResourceRecord>>(&self, index: I) -> Option<&I::Output> {
        self.answers.get(index)
    }
    pub fn get_mut_answer<I: SliceIndex<ResourceRecord>>(&mut self, index: I) -> Option<&I::Output> {
        self.answers.get_mut(index)
    }
    pub fn get_authority<I: SliceIndex<ResourceRecord>>(&self, index: I) -> Option<&I::Output> {
        self.authority.get(index)
    }
    pub fn get_mut_authority<I: SliceIndex<ResourceRecord>>(&mut self, index: I) -> Option<&I::Output> {
        self.authority.get_mut(index)
    }
    pub fn get_additional<I: SliceIndex<ResourceRecord>>(&self, index: I) -> Option<&I::Output> {
        self.additional.get(index)
    }
    pub fn get_mut_additional<I: SliceIndex<ResourceRecord>>(&mut self, index: I) -> Option<&I::Output> {
        self.additional.get_mut(index)
    }
    */
    pub fn get_question(&self, index: usize) -> Option<&Question> {
        self.questions.get(index)
    }
    pub fn get_mut_question(&mut self, index: usize) -> Option<&mut Question> {
        self.questions.get_mut(index)
    }
    pub fn get_answer(&self, index: usize) -> Option<&ResourceRecord> {
        self.answers.get(index)
    }
    pub fn get_mut_answer(&mut self, index: usize) -> Option<&mut ResourceRecord> {
        self.answers.get_mut(index)
    }
    pub fn get_authority(&self, index: usize) -> Option<&ResourceRecord> {
        self.authority.get(index)
    }
    pub fn get_mut_authority(&mut self, index: usize) -> Option<&mut ResourceRecord> {
        self.authority.get_mut(index)
    }
    pub fn get_additional(&self, index: usize) -> Option<&ResourceRecord> {
        self.additional.get(index)
    }
    pub fn get_mut_additional(&mut self, index: usize) -> Option<&mut ResourceRecord> {
        self.additional.get_mut(index)
    }

    pub fn add_question(&mut self, q: Question) {
        self.questions.push(q)
    }
    pub fn add_answer(&mut self, rr: ResourceRecord) {
        self.answers.push(rr)
    }
    pub fn add_authority(&mut self, rr: ResourceRecord) {
        self.authority.push(rr)
    }
    pub fn add_additional(&mut self, rr: ResourceRecord) {
        self.additional.push(rr)
    }

    // It would be logical to return an option instead of panicking on OOB,
    // but I'm following stdlib's lead
    pub fn remove_question(&mut self, index: usize) -> Question {
        self.questions.remove(index)
    }
    pub fn remove_answer(&mut self, index: usize) -> ResourceRecord {
        self.answers.remove(index)
    }
    pub fn remove_authority(&mut self, index: usize) -> ResourceRecord {
        self.authority.remove(index)
    }
    pub fn remove_additional(&mut self, index: usize) -> ResourceRecord {
        self.additional.remove(index)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let mut curs = Cursor::new(Vec::<u8>::new()); //FIXME: estimate size?
        try!(self.head.serialize(&mut curs));
        try!(curs.write_u16::<BigEndian>(self.questions.len() as u16));
        try!(curs.write_u16::<BigEndian>(self.answers.len() as u16));
        try!(curs.write_u16::<BigEndian>(self.authority.len() as u16));
        try!(curs.write_u16::<BigEndian>(self.additional.len() as u16));
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
    fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "DNS Message {:x}:", self.head.id)?;
        if self.head.query {
            write!(f, "\tQuery")?;
        }
        else {
            write!(f, "\tResponse")?;
        }
        writeln!(f, " for {:?}", self.head.opcode)?;
        write!(f, "\tFlags")?;
        if self.head.authoritative { write!(f, " authoritative")?; }
        if self.head.truncated { write!(f, " truncated")?; }
        if self.head.recursion_desired { write!(f, " recurse_desired")?; }
        if self.head.recursion_available { write!(f, " recurse_avail")?; }
        if self.head.authenticated_data { write!(f, " auth")?; }
        if self.head.checking_disabled { write!(f, " nocheck")?; }
        write!(f, "\n")?;
        if self.head.response_code != dns_parser::ResponseCode::NoError {
            writeln!(f, "\t{:?}", self.head.response_code)?;
        }
        Ok(())
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_header(f)?;
        if self.questions.len() != 0 { writeln!(f, "\tQuestions:")?; }
        for q in &self.questions {
            writeln!(f, "\t\t{}", q)?;
        }

        if self.answers.len() != 0 { writeln!(f, "\tAnswers:")?; }
        for a in &self.answers {
            writeln!(f, "\t\t{}", a)?;
        }

        if self.authority.len() != 0 { writeln!(f, "\tNameservers:")?; }
        for ns in &self.authority {
            writeln!(f, "\t\t{}", ns)?;
        }

        if self.additional.len() != 0 { writeln!(f, "\tAdditional RRs:")?; }
        for rr in &self.additional {
            writeln!(f, "\t\t{}", rr)?;
        }

        //TODO:  This formatting probably needs work
        if let Some(ref opt) = self.opt {
            writeln!(f, "\tRFC 6891 OPT Data:")?;
            writeln!(f, "\t\tEDNS v{}; UDP Max Size {}", opt.version , opt.udp)?;
            writeln!(f, "\t\tFlags {}", opt.flags)?;
            //TODO: OPT DATA
        }
        Ok(())
    }
}


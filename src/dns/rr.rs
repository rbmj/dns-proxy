use std::fmt;
use std::str::FromStr;
use std::io::{Cursor, Write, Seek, SeekFrom};
use std::net::{Ipv4Addr, Ipv6Addr, AddrParseError};
use byteorder::{BigEndian, WriteBytesExt};

use super::{Name, Error, Class, Type};
use dns_parser;

#[derive(Clone)]
pub struct ResourceRecord {
    pub name: Name,
    pub multicast_unique: bool,
    pub class: Class,
    pub ttl: u32,
    pub data: RRData
}

#[derive(Clone)]
pub struct OptRecord {
    pub udp: u16,
    pub extrcode: u8,
    pub version: u8,
    pub flags: u16,
    pub data: RRData
}

#[derive(Clone)]
pub struct SoaRecord {
    pub primary_ns: Name,
    pub mailbox: Name,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub min_ttl: u32
}

#[derive(Clone)]
pub struct SrvRecord {
    priority: u16,
    weight: u16,
    port: u16,
    target: Name
}

#[derive(Clone)]
pub struct MxRecord {
    preference: u16,
    exchange: Name
}

#[derive(Clone)]
pub enum RRData {
    CNAME(Name),
    NS(Name),
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    SRV(SrvRecord),
    SOA(SoaRecord),
    PTR(Name),
    MX(MxRecord),
    TXT(Vec<u8>),
    Unknown(Vec<u8>)
}

pub trait RRDataMap {
    type D;
    fn map(&RRData) -> Option<&Self::D>;
    fn map_mut(&mut RRData) -> Option<&mut Self::D>;
    fn unmap(Self::D) -> RRData;
}

pub trait RRDataUnmapStr {
    type E;
    fn unmap_str(&str) -> Result<RRData, Self::E>;
}

pub struct CNAME;
impl RRDataMap for CNAME {
    type D = Name;
    fn map(rrd: &RRData) -> Option<&Name> {
        if let &RRData::CNAME(ref n) = rrd {
            return Some(n);
        }
        None
    }
    fn map_mut(rrd: &mut RRData) -> Option<&mut Name> {
        if let &mut RRData::CNAME(ref mut n) = rrd {
            return Some(n);
        }
        None
    }
    fn unmap(n: Name) -> RRData {
        RRData::CNAME(n)
    }
}
impl RRDataUnmapStr for CNAME {
    type E = Error;
    fn unmap_str(s: &str) -> Result<RRData, Error> {
        Ok(RRData::CNAME(Name::from_str(s)?))
    }
}

pub struct A;
impl RRDataMap for A {
    type D = Ipv4Addr;
    fn map(rrd: &RRData) -> Option<&Ipv4Addr> {
        if let &RRData::A(ref addr) = rrd {
            return Some(addr);
        }
        None
    }
    fn map_mut(rrd: &mut RRData) -> Option<&mut Ipv4Addr> {
        if let &mut RRData::A(ref mut addr) = rrd {
            return Some(addr);
        }
        None
    }
    fn unmap(a: Ipv4Addr) -> RRData {
        RRData::A(a)
    }
}
impl RRDataUnmapStr for A {
    type E = AddrParseError;
    fn unmap_str(s: &str) -> Result<RRData, AddrParseError> {
        Ok(RRData::A(Ipv4Addr::from_str(s)?))
    }
}

#[derive(Debug)]
pub enum RRError<T> {
    DNS(Error),
    DataConv(T)
}

impl ResourceRecord {
    pub fn get_type(&self) -> Option<Type> {
        Some(match &self.data {
            &RRData::CNAME(_) => Type::CNAME,
            &RRData::NS(_) => Type::NS,
            &RRData::A(_) => Type::A,
            &RRData::AAAA(_) => Type::AAAA,
            &RRData::SRV(_) => Type::SRV,
            &RRData::SOA(_) => Type::SOA,
            &RRData::PTR(_) => Type::PTR,
            &RRData::MX(_) => Type::MX,
            &RRData::TXT(_) => Type::TXT,
            &RRData::Unknown(_) => return None
        })
    }
    pub fn get<T: RRDataMap>(&self) -> Option<&T::D> {
        T::map(&self.data)
    }
    pub fn get_mut<T: RRDataMap>(&mut self) -> Option<&mut T::D> {
        T::map_mut(&mut self.data)
    }
    pub fn new<T: RRDataMap>(n: Name, c: Class, d: T::D) -> Self {
        //a lot of the time the TTL is ignored so we just set a sane default
        Self::new_ttl::<T>(n, 60, c, d)
    }
    pub fn new_ttl<T: RRDataMap>(n: Name, ttl: u32, c: Class, d: T::D) -> Self {
        ResourceRecord {
            name: n,
            multicast_unique: false, //only set in mDNS
            class: c,
            ttl: ttl,
            data: T::unmap(d)
        }
    }
    pub fn new_str<T>(n: &str, c: Class, d: &str)
        -> Result<Self, RRError<<<T as RRDataMap>::D as FromStr>::Err>>
        where T: RRDataMap, T::D: FromStr
    {
        //a lot of the time the TTL is ignored so we just set a sane default
        Self::new_str_ttl::<T>(n, 60, c, d)
    }
    pub fn new_str_ttl<T>(n: &str, ttl: u32, c: Class, d: &str)
        -> Result<Self, RRError<<<T as RRDataMap>::D as FromStr>::Err>>
        where T: RRDataMap, T::D: FromStr
    {
        let name = try!(Name::from_str(n).map_err(RRError::DNS));
        let data = try!(T::D::from_str(d).map_err(RRError::DataConv));
        Ok(Self::new_ttl::<T>(name, ttl, c, data))
    }
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error> 
        where Cursor<T> : Write
    {
        try!(self.name.serialize(cursor));
        try!(cursor.write_u16::<BigEndian>(self.data.get_typenum()));
        let mut class = self.class as u16;
        if self.multicast_unique { class |= 0x8000; }
        try!(cursor.write_u16::<BigEndian>(class));
        try!(cursor.write_u32::<BigEndian>(self.ttl));
        try!(self.data.serialize(cursor));
        Ok(())
    }
    pub fn from_packet(rr: &dns_parser::ResourceRecord) -> Result<Self, Error> {
        let n = Name::from_string(rr.name.to_string())?;
        Ok(ResourceRecord{
            name: n,
            multicast_unique: rr.multicast_unique,
            class: Class::from(rr.cls),
            ttl: rr.ttl,
            data: RRData::from_packet(&rr.data)?
        })
    }
}

impl fmt::Display for ResourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        //FIXME: optionally include TTL
        match &self.data {
            &RRData::CNAME(ref n) => write!(f, "{} {:?} CNAME {}", self.name,
                self.class, n),
            &RRData::NS(ref n) => write!(f, "{} {:?} NS {}", self.name,
                self.class, n),
            &RRData::A(ref a) => write!(f, "{} {:?} A {}", self.name,
                self.class, a),
            &RRData::AAAA(ref a) => write!(f, "{} {:?} AAAA {}", self.name,
                self.class, a),
            &RRData::SRV(ref rec) => write!(f, "{} {:?} SRV {} {} {} {}",
                self.name, self.class, rec.priority, rec.weight,
                rec.port, rec.target),
            &RRData::SOA(ref rec) => write!(f,
                "{} {:?} SOA {} {} ({} {} {} {} {})", self.name,
                self.class, rec.primary_ns, rec.mailbox, rec.serial,
                rec.refresh, rec.retry, rec.expire, rec.min_ttl),
            &RRData::PTR(ref n) => write!(f, "{} {:?} PTR {}", self.name,
                self.class, n),
            &RRData::MX(ref rec) => write!(f, "{} {:?} MX {} {}", self.name,
                self.class, rec.preference, rec.exchange),
            &RRData::TXT(ref v) => write!(f, "{} {:?} TXT \"{}\"", self.name,
                self.class, String::from_utf8_lossy(&v[..])),
            &RRData::Unknown(ref v) => {
                write!(f, "{} {:?} <UNKNOWN> [", self.name, self.class)?;
                let mut first = true;
                for byte in v.iter() {
                    if !first { write!(f, ", ")?; }
                    else { first = false; }
                    write!(f, "{:X}", byte)?;
                }
                write!(f, "]")
            }
        }
    }
}

impl OptRecord {
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T> : Write
    {
        cursor.write_u8(0)?;
        cursor.write_u16::<BigEndian>(41)?; //OPT magic number
        cursor.write_u16::<BigEndian>(self.udp)?;
        cursor.write_u8(self.extrcode)?;
        cursor.write_u8(self.version)?;
        cursor.write_u16::<BigEndian>(self.flags)?;
        self.data.serialize(cursor)?;
        Ok(())
    }
    pub fn from_packet(rr: &dns_parser::OptRecord) -> Result<Self, Error> {
        Ok(OptRecord{
            udp: rr.udp,
            extrcode: rr.extrcode,
            version: rr.version,
            flags: rr.flags,
            data: RRData::from_packet(&rr.data)?})
    }
}

impl SoaRecord {
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error> 
        where Cursor<T>: Write
    {
        self.primary_ns.serialize(cursor)?;
        self.mailbox.serialize(cursor)?;
        cursor.write_u32::<BigEndian>(self.serial)?;
        cursor.write_u32::<BigEndian>(self.refresh)?;
        cursor.write_u32::<BigEndian>(self.retry)?;
        cursor.write_u32::<BigEndian>(self.expire)?;
        cursor.write_u32::<BigEndian>(self.min_ttl)?;
        Ok(())
    }
}

impl RRData {
    fn get_typenum(&self) -> u16 {
        match *self {
                RRData::CNAME(_) => 5,
                RRData::NS(_) => 2,
                RRData::A(_) => 1,
                RRData::AAAA(_) => 28,
                RRData::SRV(_) => 33,
                RRData::SOA(_) => 6,
                RRData::PTR(_) => 12,
                RRData::MX(_) => 15,
                RRData::TXT(_) => 16,
                RRData::Unknown(_) => 16 //FIXME: Fallback to TXT record until upstream changes
        }
    }
    fn from_packet(rrd: &dns_parser::RRData) -> Result<Self, Error> {
        let ret = match *rrd {
            dns_parser::RRData::CNAME(ref n) => RRData::CNAME(Name::from_string(n.to_string())?),
            dns_parser::RRData::NS(ref n) => RRData::NS(Name::from_string(n.to_string())?),
            dns_parser::RRData::A(ref a) => RRData::A(a.clone()),
            dns_parser::RRData::AAAA(ref a) => RRData::AAAA(a.clone()),
            dns_parser::RRData::SRV{priority, weight, port, target} =>
                RRData::SRV(SrvRecord{
                    priority: priority,
                    weight:  weight,
                    port: port,
                    target: Name::from_string(target.to_string())?}),
            dns_parser::RRData::SOA(ref rec) => RRData::SOA(SoaRecord{
                primary_ns: Name::from_string(rec.primary_ns.to_string())?,
                mailbox: Name::from_string(rec.mailbox.to_string())?,
                serial: rec.serial,
                refresh: rec.refresh,
                retry: rec.retry,
                expire: rec.expire,
                min_ttl: rec.minimum_ttl}),
            dns_parser::RRData::PTR(ref n) => RRData::PTR(Name::from_string(n.to_string())?),
            dns_parser::RRData::MX{preference: pref, exchange: ex} => RRData::MX(MxRecord{
                preference: pref,
                exchange: Name::from_string(ex.to_string())?}),
            dns_parser::RRData::Unknown(ref v) => RRData::Unknown(v.iter().map(|x| *x).collect()) //FIXME: Smell
        };
        Ok(ret)
    }
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error> 
        where Cursor<T> : Write
    {
        try!(cursor.write_u16::<BigEndian>(0));
        let pos = cursor.position();
        match self {
            &RRData::CNAME(ref n) => n.serialize(cursor)?,
            &RRData::NS(ref n) => n.serialize(cursor)?,
            &RRData::A(ref a) => cursor.write_all(&a.octets()[..])?,
            &RRData::AAAA(ref a) => {
                for s in a.segments().iter() {
                    cursor.write_u16::<BigEndian>(*s)?;
                }
            },
            &RRData::SRV(ref srv) => {
                cursor.write_u16::<BigEndian>(srv.priority)?;
                cursor.write_u16::<BigEndian>(srv.weight)?;
                cursor.write_u16::<BigEndian>(srv.port)?;
                srv.target.serialize(cursor)?;
            },
            &RRData::SOA(ref rec) => rec.serialize(cursor)?,
            &RRData::PTR(ref n) => n.serialize(cursor)?,
            &RRData::MX(ref mx) => {
                cursor.write_u16::<BigEndian>(mx.preference)?;
                mx.exchange.serialize(cursor)?;
            },
            &RRData::TXT(ref v) => cursor.write_all(v.as_slice())?,
            &RRData::Unknown(ref v) => cursor.write_all(v.as_slice())?
        }
        let endpos = cursor.position();
        cursor.set_position(pos-2);
        cursor.write_u16::<BigEndian>((endpos - pos) as u16)?;
        cursor.set_position(endpos);
        Ok(())
    }
}


use dns_parser;

/// The QTYPE value according to RFC 1035
///
/// All "EXPERIMENTAL" markers here are from the RFC
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Type {
    /// a host addresss
    A = 1,
    /// an authoritative name server
    NS = 2,
    /// a mail forwarder (Obsolete - use MX)
    MF = 4,
    /// the canonical name for an alias
    CNAME = 5,
    /// marks the start of a zone of authority
    SOA = 6,
    /// a mailbox domain name (EXPERIMENTAL)
    MB = 7,
    /// a mail group member (EXPERIMENTAL)
    MG = 8,
    /// a mail rename domain name (EXPERIMENTAL)
    MR = 9,
    /// a null RR (EXPERIMENTAL)
    NULL = 10,
    /// a well known service description
    WKS = 11,
    /// a domain name pointer
    PTR = 12,
    /// host information
    HINFO = 13,
    /// mailbox or mail list information
    MINFO = 14,
    /// mail exchange
    MX = 15,
    /// text strings
    TXT = 16,
    /// IPv6 host address (RFC 2782)
    AAAA = 28,
    /// service record (RFC 2782)
    SRV = 33,
    /// EDNS0 options (RFC 6891)
    OPT = 41,
    /// A request for a transfer of an entire zone
    AXFR = 252,
    /// A request for mailbox-related records (MB, MG or MR)
    MAILB = 253,
    /// A request for mail agent RRs (Obsolete - see MX)
    MAILA = 254,
    /// A request for all records
    All = 255,
}

/// The QCLASS value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Class {
    /// the Internet
    IN = 1,
    /// the CSNET class (Obsolete - used only for examples in some obsolete
    /// RFCs)
    CS = 2,
    /// the CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
    /// Any class
    Any = 255,
}

impl From<dns_parser::QueryClass> for Class {
    fn from(qc: dns_parser::QueryClass) -> Class {
        use self::Class::*;
        match qc {
            dns_parser::QueryClass::IN => IN,
            dns_parser::QueryClass::CS => CS,
            dns_parser::QueryClass::CH => CH,
            dns_parser::QueryClass::HS => HS,
            dns_parser::QueryClass::Any => Any
        }
    }
}
impl From<dns_parser::Class> for Class {
    fn from(qc: dns_parser::Class) -> Class {
        use self::Class::*;
        match qc {
            dns_parser::Class::IN => IN,
            dns_parser::Class::CS => CS,
            dns_parser::Class::CH => CH,
            dns_parser::Class::HS => HS,
        }
    }
}


impl From<dns_parser::QueryType> for Type {
    fn from(qt: dns_parser::QueryType) -> Type {
        use self::Type::*;
        match qt {
            dns_parser::QueryType::A => A,
            dns_parser::QueryType::NS => NS,
            dns_parser::QueryType::MF => MF,
            dns_parser::QueryType::CNAME => CNAME,
            dns_parser::QueryType::SOA => SOA,
            dns_parser::QueryType::MB => MB,
            dns_parser::QueryType::MG => MG,
            dns_parser::QueryType::MR => MR,
            dns_parser::QueryType::NULL => NULL,
            dns_parser::QueryType::WKS => WKS,
            dns_parser::QueryType::PTR => PTR,
            dns_parser::QueryType::HINFO => HINFO,
            dns_parser::QueryType::MINFO => MINFO,
            dns_parser::QueryType::MX => MX,
            dns_parser::QueryType::TXT => TXT,
            dns_parser::QueryType::AAAA => AAAA,
            dns_parser::QueryType::SRV => SRV,
            dns_parser::QueryType::AXFR => AXFR,
            dns_parser::QueryType::MAILB => MAILB,
            dns_parser::QueryType::MAILA => MAILA,
            dns_parser::QueryType::All => All,
        }
    }
}
impl From<dns_parser::Type> for Type {
    fn from(qt: dns_parser::Type) -> Type {
        use self::Type::*;
        match qt {
            dns_parser::Type::A => A,
            dns_parser::Type::NS => NS,
            dns_parser::Type::MF => MF,
            dns_parser::Type::CNAME => CNAME,
            dns_parser::Type::SOA => SOA,
            dns_parser::Type::MB => MB,
            dns_parser::Type::MG => MG,
            dns_parser::Type::MR => MR,
            dns_parser::Type::NULL => NULL,
            dns_parser::Type::WKS => WKS,
            dns_parser::Type::PTR => PTR,
            dns_parser::Type::HINFO => HINFO,
            dns_parser::Type::MINFO => MINFO,
            dns_parser::Type::MX => MX,
            dns_parser::Type::TXT => TXT,
            dns_parser::Type::AAAA => AAAA,
            dns_parser::Type::SRV => SRV,
            dns_parser::Type::OPT => OPT
        }
    }
}
    

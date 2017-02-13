use std;
use dns_parser;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        IOError(err: std::io::Error) {
            from()
            description("I/O Error")
            display("I/O Error: {}", err)
            cause(err)
        }
        ParserError(err: dns_parser::Error) {
            from()
            description("Parse Error")
            display("Parse Error: {}", err)
            cause(err)
        }
    }
}

mod name;
pub use self::name::{Label, Name};

mod question;
pub use self::question::{Question, QueryType, QueryClass};

mod rr;
pub use self::rr::{ResourceRecord, OptRecord, RRClass};
pub use self::rr::{RRData, SrvRecord, SoaRecord, MxRecord};

mod message;
pub use self::message::{Message, Packet};

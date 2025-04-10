use cxx::CxxString;
use std::{collections::VecDeque, pin::Pin};

#[cxx::bridge]
mod ffi {
    struct MahimahiQueuedPacket {
        arrival_time: u64,
        tun_header: u32,
        payload: Vec<u8>,
    }

    extern "Rust" {
        type WrapperPacketQueue;

        fn make_rust_queue(name: String, args: String) -> Result<Box<WrapperPacketQueue>>;
        fn make_rust_vec(x: &CxxString) -> Vec<u8>;
        fn make_cxx_string(x: Vec<u8>, out: Pin<&mut CxxString>);

        //virtual void enqueue( QueuedPacket && p ) = 0;
        fn enqueue(self: &mut WrapperPacketQueue, p: MahimahiQueuedPacket) -> Result<()>;
        //virtual QueuedPacket dequeue( void ) = 0;
        fn dequeue(self: &mut WrapperPacketQueue) -> Result<MahimahiQueuedPacket>;
        //virtual bool empty( void ) const = 0;
        fn empty(self: &WrapperPacketQueue) -> bool;
        //virtual void set_bdp( int bytes ) { (void)bytes; }
        fn set_bdp(self: &mut WrapperPacketQueue, bytes: usize);
        //virtual unsigned int size_bytes( void ) const = 0;
        fn qsize_bytes(self: &WrapperPacketQueue) -> usize;
        //virtual unsigned int size_packets( void ) const = 0;
        fn qsize_packets(self: &WrapperPacketQueue) -> usize;
        //virtual std::string to_string( void ) const = 0;
        fn to_string(self: &WrapperPacketQueue, out: Pin<&mut CxxString>);
    }
}

pub fn make_rust_vec(x: &CxxString) -> Vec<u8> {
    x.as_bytes().to_vec()
}

pub fn make_cxx_string(x: Vec<u8>, mut out: Pin<&mut CxxString>) {
    out.as_mut().clear();
    out.push_bytes(&x[..]);
}

// we cannot have a generic type parameter on this type due to CXX
pub struct WrapperPacketQueue {
    bypass: VecDeque<MahimahiQueuedPacket>,
    inner: WrapperPacketQueueInner,
}

pub enum WrapperPacketQueueInner {
    ClassTokenBucket(ClassTokenBucket),
    DeficitRoundRobin(DeficitRoundRobin),
}

// returning Err(_) from this function (and any function below) will throw an exception in C++ land.
pub fn make_rust_queue(name: String, args: String) -> Result<Box<WrapperPacketQueue>, String> {
    if let Err(e) = tracing_subscriber::fmt().try_init() {
        println!("rust_queue: could not initialize tracing: {}", e);
    }

    tracing::info!(?name, ?args, "making rust queue");
    Ok(Box::new(WrapperPacketQueue {
        bypass: Default::default(),
        inner: match name.as_str() {
            "ctb" => WrapperPacketQueueInner::ClassTokenBucket(ClassTokenBucket::new(args)?),
            "drr" => WrapperPacketQueueInner::DeficitRoundRobin(DeficitRoundRobin::new(args)?),
            _ => {
                return Err(
                    "Only ctb (ClassTokenBucket) and drr (DeficitRoundRobin) supported in Rust"
                        .to_owned(),
                )
            }
        },
    }))
}

use ffi::MahimahiQueuedPacket;
const U64_SIZE: usize = u64::BITS as usize / 8;
const U32_SIZE: usize = u32::BITS as usize / 8;

impl WrapperPacketQueue {
    pub fn enqueue(
        &mut self,
        MahimahiQueuedPacket {
            arrival_time,
            tun_header,
            payload,
        }: MahimahiQueuedPacket,
    ) -> Result<(), String> {
        match Pkt::parse_ip(payload) {
            Ok(p) => {
                let mut p: Pkt = p;
                p.buf_mut().extend(arrival_time.to_le_bytes());
                p.buf_mut().extend(tun_header.to_le_bytes());
                tracing::trace!(dport = ?p.dport(), "enqueueing packet");
                match match &mut self.inner {
                    WrapperPacketQueueInner::ClassTokenBucket(q) => q.0.enq(p),
                    WrapperPacketQueueInner::DeficitRoundRobin(q) => q.0.enq(p),
                } {
                    Ok(_) => (),
                    Err(e) => match e.downcast() {
                        Ok(p @ hwfq::Error::PacketDropped(_)) => {
                            tracing::debug!(?p, "packet dropped");
                        }
                        Ok(e) => return Err(e.to_string()),
                        Err(e) => return Err(e.to_string()),
                    },
                }
            }
            Err((payload, err)) => {
                tracing::trace!(?err, "enqueueing bypass packet");
                self.bypass.push_back(MahimahiQueuedPacket {
                    arrival_time,
                    tun_header,
                    payload,
                });
            }
        }

        Ok(())
    }

    pub fn dequeue(&mut self) -> Result<MahimahiQueuedPacket, String> {
        // ignore the non-ipv4 packets
        if let Some(p) = self.bypass.pop_front() {
            return Ok(p);
        }

        let mut p = match &mut self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => {
                q.0.deq().map_err(|x| x.to_string())?.unwrap()
            }
            WrapperPacketQueueInner::DeficitRoundRobin(q) => {
                q.0.deq().map_err(|x| x.to_string())?.unwrap()
            }
        };

        let len = p.len();
        let idx = len - U32_SIZE - U64_SIZE;
        let payload = p.buf_mut();

        let arrival_time = u64::from_le_bytes(payload[idx..idx + U64_SIZE].try_into().unwrap());
        let tun_header = u32::from_le_bytes(payload[idx + U64_SIZE..].try_into().unwrap());

        payload.truncate(idx);

        Ok(MahimahiQueuedPacket {
            arrival_time,
            tun_header,
            payload: std::mem::take(p.buf_mut()),
        })
    }

    pub fn empty(&self) -> bool {
        self.bypass.is_empty()
            && match &self.inner {
                WrapperPacketQueueInner::ClassTokenBucket(q) => q.0.is_empty(),
                WrapperPacketQueueInner::DeficitRoundRobin(q) => q.0.is_empty(),
            }
    }

    pub fn set_bdp(&mut self, bytes: usize) {
        match &mut self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => q.0.set_max_len_bytes(bytes),
            WrapperPacketQueueInner::DeficitRoundRobin(q) => q.0.set_max_len_bytes(bytes),
        }
        .unwrap();
    }

    pub fn qsize_bytes(&self) -> usize {
        // we stuff in an extra u64 + u32 into the payload per packet, so need to subtract that out.
        let size_pkts = self.qsize_packets();
        let overhead = size_pkts * (U64_SIZE + U32_SIZE);
        (match &self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => q.0.len_bytes(),
            WrapperPacketQueueInner::DeficitRoundRobin(q) => q.0.len_bytes(),
        }) - overhead
    }

    pub fn qsize_packets(&self) -> usize {
        match &self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => q.0.len_packets(),
            WrapperPacketQueueInner::DeficitRoundRobin(q) => q.0.len_packets(),
        }
    }

    pub fn to_string(&self, out: Pin<&mut CxxString>) {
        let s = match &self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => format!("{:?}", q),
            WrapperPacketQueueInner::DeficitRoundRobin(q) => format!("{:?}", q),
        };

        out.push_str(&s);
    }
}

use hwfq::{scheduler::htb::ClassedTokenBucket, scheduler::Drr, Pkt, Scheduler};

pub struct DeficitRoundRobin(Drr<true>);

impl std::fmt::Debug for DeficitRoundRobin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_tuple("DeficitRoundRobin").finish()
    }
}

impl DeficitRoundRobin {
    pub fn new(args: String) -> Result<Self, String> {
        const ERR_STR: &str = "Drr takes a single size argument in bytes: --limit-bytes={value}";
        let stripped: String = args.chars().skip_while(|x| *x == '-').collect();
        let mut split = stripped.split(&['=']);
        match split.next() {
            Some(key) if key.contains("limit-bytes") => (),
            None | Some(_) => return Err(ERR_STR.to_string()),
        }

        let limit_bytes: usize = split
            .next()
            .ok_or_else(|| ERR_STR.to_string())?
            .parse()
            .map_err(|e| format!("{}: error parsing value as usize: {}", ERR_STR, e))?;
        Ok(DeficitRoundRobin(Drr::<true>::new(limit_bytes)))
    }
}

#[derive(Debug)]
pub struct ClassTokenBucket(ClassedTokenBucket<std::fs::File>);

impl ClassTokenBucket {
    pub fn new(args: String) -> Result<Self, String> {
        Ok(ClassTokenBucket(
            args.parse().map_err(|e| format!("{}", e))?,
        ))
    }
}

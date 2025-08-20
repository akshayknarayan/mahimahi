use cxx::CxxString;
use std::{collections::VecDeque, pin::Pin, time::{Instant, Duration},};
mod tp;
use tp::{TrafficPolicerCommonBucket, TrafficPolicerMultiBucket, TrafficPolicerHybrid};

use std::fs::OpenOptions;
use std::io::Write;

pub fn log_to_file(msg: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("script/logs/token_log.csv")
        .expect("could not open log file");

    writeln!(file, "{}", msg).expect("could not write to log file");
}

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
    last_enq: Option<Instant>,
}

pub enum WrapperPacketQueueInner {
    ClassTokenBucket(ClassTokenBucket),
    DeficitRoundRobin(DeficitRoundRobin),
    TrafficPolicerCommonBucket(TrafficPolicerCommonBucket<std::io::Empty>),
    TrafficPolicerMultiBucket(TrafficPolicerMultiBucket<std::io::Empty>),
    TrafficPolicerHybrid(TrafficPolicerHybrid<std::io::Empty>)
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
            "tpc" => WrapperPacketQueueInner::TrafficPolicerCommonBucket(
                TrafficPolicerCommonBucket::new(args).map_err(|e| e.to_string())?),
            "tpm" => WrapperPacketQueueInner::TrafficPolicerMultiBucket(
                TrafficPolicerMultiBucket::new(args).map_err(|e| e.to_string())?),
            "tph" => WrapperPacketQueueInner::TrafficPolicerHybrid(
                TrafficPolicerHybrid::new(args).map_err(|e| e.to_string())?),
            _ => {
                return Err(
                    "Only ctb (ClassTokenBucket), drr (DeficitRoundRobin), tpc (TrafficPolicerCommonBucket), 
                    tpm (TrafficPolicerMultiBucket), and tph (TrafficPolicerHybrid) supported in Rust"
                    .to_owned(),
                )
            }
        },
        last_enq:Some(Instant::now())
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
                    WrapperPacketQueueInner::TrafficPolicerCommonBucket(q) => q.enq(p),
                    WrapperPacketQueueInner::TrafficPolicerMultiBucket(q) => q.enq(p),
                    WrapperPacketQueueInner::TrafficPolicerHybrid(q) => q.enq(p),
                    WrapperPacketQueueInner::DeficitRoundRobin(q) => {
                        match self.last_enq {
                            None => self.last_enq = Some(Instant::now()),
                            Some(last_enq) => {
                                if Instant::now().duration_since(last_enq) > Duration::from_millis(500) {
                                    q.0.dbg(Duration::ZERO);
                                    self.last_enq = Some(Instant::now());
                                }
                            }
                        };

                        q.0.enq(p)
                    },
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
            WrapperPacketQueueInner::TrafficPolicerCommonBucket(q) => {
                q.deq().map_err(|x| x.to_string())?.unwrap()
            }
            WrapperPacketQueueInner::TrafficPolicerMultiBucket(q) => {
                q.deq().map_err(|x| x.to_string())?.unwrap()
            }
            WrapperPacketQueueInner::TrafficPolicerHybrid(q) => {
                q.deq().map_err(|x| x.to_string())?.unwrap()
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
                WrapperPacketQueueInner::TrafficPolicerCommonBucket(q) => q.is_empty(),
                WrapperPacketQueueInner::TrafficPolicerMultiBucket(q) => q.is_empty(),
                WrapperPacketQueueInner::TrafficPolicerHybrid(q) => q.is_empty(),
            }
    }

    pub fn set_bdp(&mut self, bytes: usize) {
        match &mut self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => q.0.set_max_len_bytes(bytes),
            WrapperPacketQueueInner::DeficitRoundRobin(q) => q.0.set_max_len_bytes(bytes),
            WrapperPacketQueueInner::TrafficPolicerCommonBucket(q) => q.set_max_len_bytes(bytes),
            WrapperPacketQueueInner::TrafficPolicerMultiBucket(q) => q.set_max_len_bytes(bytes),
            WrapperPacketQueueInner::TrafficPolicerHybrid(q) => q.set_max_len_bytes(bytes),
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
            WrapperPacketQueueInner::TrafficPolicerCommonBucket(q) => q.len_bytes(),
            WrapperPacketQueueInner::TrafficPolicerMultiBucket(q) => q.len_bytes(),
            WrapperPacketQueueInner::TrafficPolicerHybrid(q) => q.len_bytes(),
        }) - overhead
    }

    pub fn qsize_packets(&self) -> usize {
        match &self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => q.0.len_packets(),
            WrapperPacketQueueInner::DeficitRoundRobin(q) => q.0.len_packets(),
            WrapperPacketQueueInner::TrafficPolicerCommonBucket(q) => q.len_packets(),
            WrapperPacketQueueInner::TrafficPolicerMultiBucket(q) => q.len_packets(),
            WrapperPacketQueueInner::TrafficPolicerHybrid(q) => q.len_packets(),
        }
    }

    pub fn to_string(&self, out: Pin<&mut CxxString>) {
        let s = match &self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => format!("{:?}", q),
            WrapperPacketQueueInner::DeficitRoundRobin(q) => format!("{:?}", q),
            WrapperPacketQueueInner::TrafficPolicerCommonBucket(q) => format!("{:?}", q),
            WrapperPacketQueueInner::TrafficPolicerMultiBucket(q) => format!("{:?}", q),
            WrapperPacketQueueInner::TrafficPolicerHybrid(q) => format!("{:?}", q),
        };

        out.push_str(&s);
    }
}

use hwfq::{scheduler::htb::ClassedTokenBucket, scheduler::drr::Drr, Pkt, Scheduler};

pub struct DeficitRoundRobin(Drr<true, std::fs::File>);

impl std::fmt::Debug for DeficitRoundRobin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_tuple("DeficitRoundRobin").finish()
    }
}

impl DeficitRoundRobin {
    pub fn new(args: String) -> Result<Self, String> {
        Ok(DeficitRoundRobin(args.parse().map_err(|e| format!("{}", e))?,))
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

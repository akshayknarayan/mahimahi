use cxx::CxxString;
use std::{collections::VecDeque, pin::Pin};
use eyre::Report;
use eyre::bail;
use tracing::debug;
use quanta::Instant;
use std::time::Duration;

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
    TrafficPolicer(TrafficPolicer<std::io::Empty>),
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
            "tp" => WrapperPacketQueueInner::TrafficPolicer(TrafficPolicer::new(args).map_err(|e| e.to_string())?),
            _ => {
                return Err(
                    "Only ctb (ClassTokenBucket), drr (DeficitRoundRobin), and tp (TrafficPolicer) supported in Rust"
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
                    WrapperPacketQueueInner::TrafficPolicer(q) => q.enq(p),
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
            WrapperPacketQueueInner::TrafficPolicer(q) => {
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
                WrapperPacketQueueInner::TrafficPolicer(q) => q.is_empty(),
            }
    }

    pub fn set_bdp(&mut self, bytes: usize) {
        match &mut self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => q.0.set_max_len_bytes(bytes),
            WrapperPacketQueueInner::DeficitRoundRobin(q) => q.0.set_max_len_bytes(bytes),
            WrapperPacketQueueInner::TrafficPolicer(q) => q.set_max_len_bytes(bytes),
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
            WrapperPacketQueueInner::TrafficPolicer(q) => q.len_bytes(),
        }) - overhead
    }

    pub fn qsize_packets(&self) -> usize {
        match &self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => q.0.len_packets(),
            WrapperPacketQueueInner::DeficitRoundRobin(q) => q.0.len_packets(),
            WrapperPacketQueueInner::TrafficPolicer(q) => q.len_packets(),
        }
    }

    pub fn to_string(&self, out: Pin<&mut CxxString>) {
        let s = match &self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => format!("{:?}", q),
            WrapperPacketQueueInner::DeficitRoundRobin(q) => format!("{:?}", q),
            WrapperPacketQueueInner::TrafficPolicer(q) => format!("{:?}", q),
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

#[derive(Debug)]
pub struct RateCounter {
    epoch_rate_bytes: usize,
    epoch_borrowed_bytes: usize,
}

impl RateCounter {
    pub fn new() -> Self {
        RateCounter {
            epoch_rate_bytes: 0,
            epoch_borrowed_bytes: 0,
        }
    }

    pub fn record_rate_bytes(&mut self, len: usize) {
        self.epoch_rate_bytes += len;
    }

    pub fn record_borrowed_bytes(&mut self, len: usize) {
        self.epoch_borrowed_bytes += len;
    }

    pub fn log(
        &mut self,
        elapsed: Duration,
        logger: Option<&mut csv::Writer<impl std::io::Write>>,
    ) {
        if self.epoch_rate_bytes == 0 && self.epoch_borrowed_bytes == 0 {
            return;
        }

        if let Some(log) = logger {
            #[derive(serde::Serialize)]
            struct Record {
                unix_time_ms: u128,
                epoch_rate_bytes: usize,
                epoch_borrowed_bytes: usize,
                epoch_elapsed_ms: u128,
            }

            if let Err(err) = log.serialize(Record {
                unix_time_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
                epoch_rate_bytes: self.epoch_rate_bytes,
                epoch_borrowed_bytes: self.epoch_borrowed_bytes,
                epoch_elapsed_ms: elapsed.as_millis(),
            }) {
                debug!(?err, "write to logger failed");
            }
        }

        debug!(?self.epoch_rate_bytes, ?self.epoch_borrowed_bytes, ?elapsed, "rate counter log");

        self.epoch_rate_bytes = 0;
        self.epoch_borrowed_bytes = 0;
    }

    pub fn reset(&mut self) {
        if self.epoch_rate_bytes > 0 || self.epoch_borrowed_bytes > 0 {
            debug!(?self.epoch_rate_bytes, ?self.epoch_borrowed_bytes, "rate counter reset");
        }

        self.epoch_rate_bytes = 0;
        self.epoch_borrowed_bytes = 0;
    }
}


#[derive(Debug)]
pub struct TokenBucket {
    rate_bytes_per_sec: usize,
    accum_bytes: usize,
    last_incr: Option<Instant>,
}

impl TokenBucket {
    pub fn new(rate_bytes_per_sec: usize) -> Self {
        Self {
            rate_bytes_per_sec,
            accum_bytes: 1514,
            last_incr: None,
        }
    }

    fn accumulate(&mut self) {
        let last_incr = match self.last_incr {
            Some(t) => t,
            None => {
                self.last_incr = Some(Instant::now());
                return;
            }
        };

        self.accum_bytes +=
            (last_incr.elapsed().as_secs_f64() * self.rate_bytes_per_sec as f64) as usize;
        self.last_incr = Some(Instant::now());
    }

    fn reset(&mut self) {
        self.last_incr = None;
        self.accum_bytes = 1514; // one packet
    }
}

#[derive(Debug)]
pub struct TrafficPolicer<L: std::io::Write> {
    max_len_bytes: usize,
    tb: TokenBucket,
    queue: VecDeque<Pkt>,
    ctr: RateCounter,
    logger: Option<csv::Writer<L>>,
}

impl<L: std::io::Write> TrafficPolicer<L> {
    pub fn with_logger<W: std::io::Write>(self, w: W) -> TrafficPolicer<W> {
        self.maybe_with_logger(Some(w))
    }

    pub fn maybe_with_logger<W: std::io::Write>(self, w: Option<W>) -> TrafficPolicer<W> {
        TrafficPolicer {
            max_len_bytes: self.max_len_bytes,
            tb: self.tb, 
            queue: self.queue,
            ctr: self.ctr,
            logger: w.map(|x| csv::Writer::from_writer(x)),
        }
    }
}

impl TrafficPolicer<std::io::Empty> {
    pub fn new(args: String) -> Result<Self, Report> {
        const ERR_STR: &str = "Tp takes two arguments: --max_len_bytes={value}, --rate_bytes_per_sec={value}";
        let mut max_len_bytes: Option<usize> = None;
        let mut rate_bytes_per_sec: Option<usize> = None;

        for arg in args.split_whitespace() {
            let stripped: String = arg.chars().skip_while(|x| *x == '-').collect();
            let mut split = stripped.split('=');

            let key = split.next();
            let value = split.next();

            match (key, value) {
                (Some(k), Some(v)) if k.contains("max_len_bytes") => {
                    max_len_bytes = Some(v
                        .parse()
                        .map_err(|e| Report::msg(format!("{}: error parsing max_len_bytes: {}", ERR_STR, e)))?)
                }
                (Some(k), Some(v)) if k == "rate_bytes_per_sec" => {
                    rate_bytes_per_sec = Some(v
                        .parse()
                        .map_err(|e| Report::msg(format!("{}: error parsing rate_bytes_per_sec: {}", ERR_STR, e)))?);
                }
                _ => return Err(Report::msg(ERR_STR)),
            }
        }

        let max_len = max_len_bytes.ok_or_else(|| Report::msg(ERR_STR))?;
        let rate = rate_bytes_per_sec.ok_or_else(|| Report::msg(ERR_STR))?;

        Ok(Self {
            max_len_bytes: max_len,
            tb: TokenBucket::new(rate), 
            queue: Default::default(),
            ctr: RateCounter::new(),
            logger: None,
        })
    }
}

impl<L: std::io::Write> Scheduler for TrafficPolicer<L> {
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        let tot_curr_len_bytes: usize = self.len_bytes();
        self.tb.accumulate();
        if p.len() >= self.tb.accum_bytes || p.len() + tot_curr_len_bytes >= self.max_len_bytes {
            bail!(hwfq::Error::PacketDropped(p));
        }

        self.queue.push_back(p);

        Ok(())
    }

    fn deq(&mut self) -> Result<Option<Pkt>, Report> {
        if let Some(p) = self.queue.front() {
            self.tb.accumulate();
            if p.len() <= self.tb.accum_bytes {
                self.tb.accum_bytes -= p.len();
                let pkt = self.queue.pop_front().unwrap();
                return Ok(Some(pkt));
            } 
        }
        self.tb.reset();
        return Ok(None)
    }

    fn len_bytes(&self) -> usize {
        self.queue.iter().map(|p| p.len()).sum()
    }

    fn len_packets(&self) -> usize {
        self.queue.len()
    }

    fn is_empty(&self) -> bool {
        if let Some(p) = self.queue.front() {
            return p.len() > self.tb.accum_bytes;
        }
        return true
    }

    fn set_max_len_bytes(&mut self, bytes: usize) -> Result<(), Report> {
        self.max_len_bytes = bytes;
        Ok(())
    }

    fn dbg(&mut self, epoch_dur: Duration) {
        self.ctr.log(epoch_dur, self.logger.as_mut())
    }

}

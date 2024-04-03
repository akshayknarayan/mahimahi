use cxx::CxxString;
use std::{collections::VecDeque, pin::Pin};

#[cxx::bridge]
mod ffi {
    struct MahimahiQueuedPacket {
        arrival_time: u64,
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

pub struct WrapperPacketQueue {
    bypass: VecDeque<MahimahiQueuedPacket>,
    inner: WrapperPacketQueueInner,
}

pub enum WrapperPacketQueueInner {
    ClassTokenBucket(ClassTokenBucket),
}

pub fn make_rust_queue(name: String, args: String) -> Result<Box<WrapperPacketQueue>, String> {
    println!("making rust queue with name {}, args: ({})", name, args);
    Ok(Box::new(WrapperPacketQueue {
        bypass: Default::default(),
        inner: WrapperPacketQueueInner::ClassTokenBucket(ClassTokenBucket::new(args)?),
    }))
}

use ffi::MahimahiQueuedPacket;

impl WrapperPacketQueue {
    pub fn enqueue(
        &mut self,
        MahimahiQueuedPacket {
            arrival_time,
            payload,
        }: MahimahiQueuedPacket,
    ) -> Result<(), String> {
        match payload.try_into() {
            Ok(p) => {
                let mut p: Pkt = p;
                p.buf_mut().extend(arrival_time.to_le_bytes());
                match &mut self.inner {
                    WrapperPacketQueueInner::ClassTokenBucket(q) => {
                        q.0.enq(p).map_err(|x| x.to_string())?
                    }
                }
            }
            Err((payload, _err)) => {
                self.bypass.push_back(MahimahiQueuedPacket {
                    arrival_time,
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
        };

        let len = p.len();
        const SIZE: usize = u64::BITS as usize / 8;
        let idx = len - SIZE;
        let payload = p.buf_mut();

        let arrival_time = u64::from_le_bytes(payload[idx..].try_into().unwrap());
        payload.truncate(idx);

        Ok(MahimahiQueuedPacket {
            arrival_time,
            payload: std::mem::take(p.buf_mut()),
        })
    }

    pub fn empty(&self) -> bool {
        self.bypass.is_empty()
            && match &self.inner {
                WrapperPacketQueueInner::ClassTokenBucket(q) => q.0.is_empty(),
            }
    }

    pub fn set_bdp(&mut self, bytes: usize) {
        match &mut self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => q.0.set_max_len_bytes(bytes),
        }
    }

    pub fn qsize_bytes(&self) -> usize {
        match &self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => q.0.tot_len_bytes(),
        }
    }

    pub fn qsize_packets(&self) -> usize {
        match &self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => q.0.tot_len_pkts(),
        }
    }

    pub fn to_string(&self, out: Pin<&mut CxxString>) {
        let s = match &self.inner {
            WrapperPacketQueueInner::ClassTokenBucket(q) => format!("{:?}", q),
        };

        out.push_str(&s);
    }
}

use hwfq::{scheduler::htb::ClassedTokenBucket, Pkt, Scheduler};

#[derive(Debug)]
pub struct ClassTokenBucket(ClassedTokenBucket);

impl ClassTokenBucket {
    pub fn new(args: String) -> Result<Self, String> {
        Ok(ClassTokenBucket(
            args.parse().map_err(|e| format!("{}", e))?,
        ))
    }
}

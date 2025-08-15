use eyre::bail;
use eyre::Report;
use hwfq::{scheduler::htb::RateCounter, Pkt, Scheduler};
use quanta::Instant;
use std::collections::VecDeque;
use std::time::Duration;
use crate::log_to_file;

#[derive(Debug)]
pub struct TokenBucket {
    rate_bytes_per_sec: usize,
    accum_bytes: f64,
    bucket_size: f64,
    last_incr: Instant,
}

impl TokenBucket {
    pub fn new(rate_bytes_per_sec: usize) -> Self {
        Self {
            rate_bytes_per_sec,
            accum_bytes: 0.0,
            bucket_size: 360000.0,
            last_incr: Instant::now(),
        }
    }

    fn accumulate(&mut self) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_incr).as_secs_f64();
        self.accum_bytes += elapsed * (self.rate_bytes_per_sec as f64);
        if self.accum_bytes > self.bucket_size {
            self.accum_bytes = self.bucket_size
        }
        self.last_incr = now;
    }
}

#[derive(Debug)]
pub struct TrafficPolicerCommonBucket<L: std::io::Write> {
    max_len_bytes: usize,
    tb: TokenBucket,
    queue: VecDeque<Pkt>,
    ctr: RateCounter,
    logger: Option<csv::Writer<L>>,
    start_time: Instant,
}

impl<L: std::io::Write> TrafficPolicerCommonBucket<L> {
    pub fn with_logger<W: std::io::Write>(self, w: W) -> TrafficPolicerCommonBucket<W> {
        self.maybe_with_logger(Some(w))
    }

    pub fn maybe_with_logger<W: std::io::Write>(self, w: Option<W>) -> TrafficPolicerCommonBucket<W> {
        TrafficPolicerCommonBucket {
            max_len_bytes: self.max_len_bytes,
            tb: self.tb,
            queue: self.queue,
            ctr: self.ctr,
            logger: w.map(|x| csv::Writer::from_writer(x)),
            start_time: self.start_time,
        }
    }
}

impl TrafficPolicerCommonBucket<std::io::Empty> {
    pub fn new(args: String) -> Result<Self, Report> {
        const ERR_STR: &str =
            "TPC takes two arguments: --max_len_bytes={value}, --rate_bytes_per_sec={value}";
        let mut max_len_bytes: Option<usize> = None;
        let mut rate_bytes_per_sec: Option<usize> = None;

        for arg in args.split_whitespace() {
            let stripped: String = arg.chars().skip_while(|x| *x == '-').collect();
            let mut split = stripped.split('=');

            let key = split.next();
            let value = split.next();

            match (key, value) {
                (Some(k), Some(v)) if k.contains("max_len_bytes") => {
                    max_len_bytes = Some(v.parse().map_err(|e| {
                        Report::msg(format!("{}: error parsing max_len_bytes: {}", ERR_STR, e))
                    })?)
                }
                (Some(k), Some(v)) if k == "rate_bytes_per_sec" => {
                    rate_bytes_per_sec = Some(v.parse().map_err(|e| {
                        Report::msg(format!(
                            "{}: error parsing rate_bytes_per_sec: {}",
                            ERR_STR, e
                        ))
                    })?);
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
            ctr: RateCounter::new(None),
            logger: None,
            start_time: Instant::now(),
        })
    }
}

impl<L: std::io::Write> Scheduler for TrafficPolicerCommonBucket<L> {
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        // let timestamp = self.tb.last_incr.duration_since(self.start_time).as_secs_f64();
        // log_to_file(&format!("{:.3}, {}", timestamp, self.tb.accum_bytes));

        self.tb.accumulate();

        // let timestamp = self.start_time.elapsed().as_secs_f64();
        // log_to_file(&format!("{:.3}, {}", timestamp, self.tb.accum_bytes));

        if p.len() > self.tb.accum_bytes as usize
            || p.len() + self.len_bytes() > self.max_len_bytes
        {
            bail!(hwfq::Error::PacketDropped(p));
        }

        self.tb.accum_bytes -= p.len() as f64;
        self.queue.push_back(p);

        // let timestamp = self.start_time.elapsed().as_secs_f64();
        // log_to_file(&format!("{:.3}, {}", timestamp, self.tb.accum_bytes));

        Ok(())
    }

    fn deq(&mut self) -> Result<Option<Pkt>, Report> {
        self.tb.accumulate();
        // let timestamp = self.start_time.elapsed().as_secs_f64();
        // log_to_file(&format!("{:.3}, {}", timestamp, self.tb.accum_bytes));

        match self.queue.front() {
            None => Ok(None),
            Some(_) => {
                let pkt = self.queue.pop_front().unwrap();
                return Ok(Some(pkt));
            }
        }
    }

    fn len_bytes(&self) -> usize {
        self.queue.iter().map(|p| p.len()).sum()
    }

    fn len_packets(&self) -> usize {
        self.queue.len()
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn set_max_len_bytes(&mut self, bytes: usize) -> Result<(), Report> {
        self.max_len_bytes = bytes;
        Ok(())
    }

    fn dbg(&mut self, epoch_dur: Duration) {
        self.ctr.log(epoch_dur, self.logger.as_mut())
    }
}

#[derive(Debug)]
pub struct TrafficPolicerMultiBucket<L: std::io::Write> {
   max_len_bytes: usize,
   buckets: Vec<TokenBucket>,
   dport_to_idx: Vec<(u16, usize)>,
   queue: VecDeque<Pkt>,
   ctr: RateCounter,
   logger: Option<csv::Writer<L>>,
   start_time: Instant,
}

impl TrafficPolicerMultiBucket<std::io::Empty> {
   pub fn new(args: String) -> Result<Self, Report> {
       const ERR_STR: &str =
           "TPM takes four arguments: --max_len_bytes={value} --rate_bytes_per_sec={value} --num_flows={value} --dports={list}";
       let mut max_len_bytes: Option<usize> = None;
       let mut rate_bytes_per_sec: Option<usize> = None;
       let mut num_flows: Option<usize> = None;
       let mut dports: Option<Vec<u16>> = None;

       for arg in args.split_whitespace() {
           let stripped: String = arg.chars().skip_while(|x| *x == '-').collect();
           let mut split = stripped.split('=');

           let key = split.next();
           let value = split.next();

           match (key, value) {
               (Some(k), Some(v)) if k.contains("max_len_bytes") => {
                   max_len_bytes = Some(v.parse().map_err(|e| {
                       Report::msg(format!("{}: error parsing max_len_bytes: {}", ERR_STR, e))
                   })?)
               }
               (Some(k), Some(v)) if k == "rate_bytes_per_sec" => {
                   rate_bytes_per_sec = Some(v.parse().map_err(|e| {
                       Report::msg(format!(
                           "{}: error parsing rate_bytes_per_sec: {}",
                           ERR_STR, e
                       ))
                   })?);
               }
               (Some(k), Some(v)) if k == "num_flows" => {
                   num_flows = Some(v.parse().map_err(|e| {
                       Report::msg(format!(
                           "{}: error parsing num_flows: {}",
                           ERR_STR, e
                       ))
                   })?);
               }
               (Some(k), Some(v)) if k == "dports" => {
                   let parsed: Result<Vec<u16>, _> = v
                       .split(',')
                       .map(|s| s.parse::<u16>())
                       .collect();
                   dports = Some(parsed.map_err(|e| {
                       Report::msg(format!("{}: error parsing dports list: {}", ERR_STR, e))
                   })?);
               }
               _ => return Err(Report::msg(ERR_STR)),
           }
       }

       let max_len = max_len_bytes.ok_or_else(|| Report::msg(ERR_STR))?;
       let rate = rate_bytes_per_sec.ok_or_else(|| Report::msg(ERR_STR))?;
       let ports = dports.ok_or_else(|| Report::msg(ERR_STR))?;
       let flows = num_flows.ok_or_else(|| Report::msg(ERR_STR))?;
       let bucket_rate = rate / flows;

       let mut dport_to_idx = Vec::new();
       let mut buckets = Vec::new();
       for p in ports {
           dport_to_idx.push((p, buckets.len()));
           buckets.push(TokenBucket::new(bucket_rate));
       }

       Ok(Self {
           max_len_bytes: max_len,
           buckets: buckets,
           dport_to_idx: dport_to_idx,
           queue: Default::default(),
           ctr: RateCounter::new(None),
           logger: None,
           start_time: Instant::now()
       })
   }
}

impl<L: std::io::Write> TrafficPolicerMultiBucket<L> {
   pub fn with_logger<W: std::io::Write>(self, w: W) -> TrafficPolicerMultiBucket<W> {
       self.maybe_with_logger(Some(w))
   }

   pub fn maybe_with_logger<W: std::io::Write>(self, w: Option<W>) -> TrafficPolicerMultiBucket<W> {
       TrafficPolicerMultiBucket {
           max_len_bytes: self.max_len_bytes,
           buckets: self.buckets,
           dport_to_idx: self.dport_to_idx,
           queue: self.queue,
           ctr: self.ctr,
           logger: w.map(|x| csv::Writer::from_writer(x)),
           start_time: self.start_time
       }
   }
}

impl<L: std::io::Write> Scheduler for TrafficPolicerMultiBucket<L> {
   fn enq(&mut self, p: Pkt) -> Result<(), Report> {
       let idx;
       if let Some((_, i)) = self.dport_to_idx.iter().find(|&&(x, _)| x == p.dport()) {
           idx = Some(*i);
       } else {
           bail!(hwfq::Error::PacketDropped(p));
       }

       let queue_len = self.len_bytes();

       // let bucket_0 = &mut self.buckets[0];
       // let timestamp = bucket_0.last_incr.duration_since(self.start_time).as_secs_f64();
       // log_to_file(&format!("{:.3}, {}", timestamp, bucket_0.accum_bytes));

       let bucket = &mut self.buckets[idx.unwrap()];
       bucket.accumulate();

       // let bucket_0 = &mut self.buckets[0];
       // let timestamp = self.start_time.elapsed().as_secs_f64();
       // log_to_file(&format!("{:.3}, {}", timestamp, bucket_0.accum_bytes));
       // let bucket = &mut self.buckets[idx.unwrap()];

       if p.len() > bucket.accum_bytes as usize
           || p.len() + queue_len > self.max_len_bytes
       {
           bail!(hwfq::Error::PacketDropped(p));
       }
       bucket.accum_bytes -= p.len() as f64;
       self.queue.push_back(p);

       // let bucket_0 = &mut self.buckets[0];
       // let timestamp = self.start_time.elapsed().as_secs_f64();
       // log_to_file(&format!("{:.3}, {}", timestamp, bucket_0.accum_bytes));

       Ok(())
   }

   fn deq(&mut self) -> Result<Option<Pkt>, Report> {
       // let bucket_0 = &mut self.buckets[0];
       // bucket_0.accumulate();
       // let timestamp = self.start_time.elapsed().as_secs_f64();
       // log_to_file(&format!("{:.3}, {}", timestamp, bucket_0.accum_bytes));

       match self.queue.front() {
           None => Ok(None),
           Some(_) => {
               let pkt = self.queue.pop_front().unwrap();
               return Ok(Some(pkt));
           }
       }
   }

   fn len_bytes(&self) -> usize {
       self.queue.iter().map(|p| p.len()).sum()
   }

   fn len_packets(&self) -> usize {
       self.queue.len()
   }

   fn is_empty(&self) -> bool {
       return self.queue.is_empty()
   }

   fn set_max_len_bytes(&mut self, bytes: usize) -> Result<(), Report> {
       self.max_len_bytes = bytes;
       Ok(())
   }

   fn dbg(&mut self, epoch_dur: Duration) {
       self.ctr.log(epoch_dur, self.logger.as_mut());
   }
}


#[derive(Debug)]
pub struct TrafficPolicerHybrid<L: std::io::Write> {
    max_len_bytes: usize,
    buckets: Vec<TokenBucket>,
    dport_to_idx: Vec<(u16, usize)>,
    queue: VecDeque<Pkt>,
    ctr: RateCounter,
    logger: Option<csv::Writer<L>>,
}

impl TrafficPolicerHybrid<std::io::Empty> {
    pub fn new(args: String) -> Result<Self, Report> {
        const ERR_STR: &str =
            "TPH takes four arguments: --max_len_bytes={value} --rate_bytes_per_sec={value} 
            --num_flows={value} --dports={list}";
        let mut max_len_bytes: Option<usize> = None;
        let mut rate_bytes_per_sec: Option<usize> = None;
        let mut num_flows: Option<usize> = None;
        let mut dports: Option<Vec<u16>> = None;

        for arg in args.split_whitespace() {
            let stripped: String = arg.chars().skip_while(|x| *x == '-').collect();
            let mut split = stripped.split('=');

            let key = split.next();
            let value = split.next();

            match (key, value) {
                (Some(k), Some(v)) if k.contains("max_len_bytes") => {
                    max_len_bytes = Some(v.parse().map_err(|e| {
                        Report::msg(format!("{}: error parsing max_len_bytes: {}", ERR_STR, e))
                    })?)
                }
                (Some(k), Some(v)) if k == "rate_bytes_per_sec" => {
                    rate_bytes_per_sec = Some(v.parse().map_err(|e| {
                        Report::msg(format!(
                            "{}: error parsing rate_bytes_per_sec: {}",
                            ERR_STR, e
                        ))
                    })?);
                }
                (Some(k), Some(v)) if k == "num_flows" => {
                    num_flows = Some(v.parse().map_err(|e| {
                        Report::msg(format!(
                            "{}: error parsing num_flows: {}",
                            ERR_STR, e
                        ))
                    })?);
                }
                (Some(k), Some(v)) if k == "dports" => {
                    let parsed: Result<Vec<u16>, _> = v
                        .split(',')
                        .map(|s| s.parse::<u16>())
                        .collect();
                    dports = Some(parsed.map_err(|e| {
                        Report::msg(format!("{}: error parsing dports list: {}", ERR_STR, e))
                    })?);
                }
                _ => return Err(Report::msg(ERR_STR)),
            }
        }

        let max_len = max_len_bytes.ok_or_else(|| Report::msg(ERR_STR))?;
        let rate = rate_bytes_per_sec.ok_or_else(|| Report::msg(ERR_STR))?;
        let ports = dports.ok_or_else(|| Report::msg(ERR_STR))?;
        let flows = num_flows.ok_or_else(|| Report::msg(ERR_STR))?;
        let default_rate = rate / (flows + 1);
        let bucket_rate = (rate - default) / flows;

        let mut dport_to_idx = Vec::new();
        let mut buckets = Vec::new();
        buckets.push(TokenBucket::new(default_rate));
        for p in ports {
            dport_to_idx.push((p, buckets.len()));
            buckets.push(TokenBucket::new(bucket_rate));
        }

        Ok(Self {
            max_len_bytes: max_len,
            buckets: buckets,
            dport_to_idx: dport_to_idx,
            queue: Default::default(),
            ctr: RateCounter::new(None),
            logger: None,
        })
    }
}

impl<L: std::io::Write> TrafficPolicerHybrid<L> {
    pub fn with_logger<W: std::io::Write>(self, w: W) -> TrafficPolicerHybrid<W> {
        self.maybe_with_logger(Some(w))
    }

    pub fn maybe_with_logger<W: std::io::Write>(self, w: Option<W>) -> TrafficPolicerHybrid<W> {
        TrafficPolicerHybrid {
            max_len_bytes: self.max_len_bytes,
            buckets: self.buckets,
            dport_to_idx: self.dport_to_idx,
            queue: self.queue,
            ctr: self.ctr,
            logger: w.map(|x| csv::Writer::from_writer(x)),
        }
    }
}

impl<L: std::io::Write> Scheduler for TrafficPolicerHybrid<L> {
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        let idx;
        if let Some((_, i)) = self.dport_to_idx.iter().find(|&&(x, _)| x == p.dport()) {
            idx = Some(*i);
        } else {
            bail!(hwfq::Error::PacketDropped(p));
        }

        if p.len() + self.len_bytes() > self.max_len_bytes
        {
            bail!(hwfq::Error::PacketDropped(p));
        }

        let bucket = &mut self.buckets[idx.unwrap()];
        bucket.accumulate();
        if p.len() <= bucket.accum_bytes as usize {
            bucket.accum_bytes -= p.len() as f64;
            self.queue.push_back(p);
            return Ok(())
        }

        let default = &mut self.buckets[0];
        default.accumulate();
        if p.len() <= default.accum_bytes as usize {
            default.accum_bytes -= p.len() as f64;
            self.queue.push_back(p);
            return Ok(())
        }

        bail!(hwfq::Error::PacketDropped(p));
    }

    fn deq(&mut self) -> Result<Option<Pkt>, Report> {
        match self.queue.front() {
            None => Ok(None),
            Some(_) => {
                let pkt = self.queue.pop_front().unwrap();
                return Ok(Some(pkt));
            }
        }
    }

    fn len_bytes(&self) -> usize {
        self.queue.iter().map(|p| p.len()).sum()
    }

    fn len_packets(&self) -> usize {
        self.queue.len()
    }

    fn is_empty(&self) -> bool {
        return self.queue.is_empty();
    }

    fn set_max_len_bytes(&mut self, bytes: usize) -> Result<(), Report> {
        self.max_len_bytes = bytes;
        Ok(())
    }

    fn dbg(&mut self, epoch_dur: Duration) {
        self.ctr.log(epoch_dur, self.logger.as_mut())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use rand::Rng;

    fn pkt_parse_1() -> Pkt {
        let buf = vec![
            // IPv4 Header
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, 17, 0x00, 0x00, 
            192, 168, 0, 1, 192, 168, 0, 2, 
            // UDP Header
            0x04, 0xd2, // source port
            0x16, 0x2e, // dport 5678
            0x00, 0x08, // length (header only)
            0x00, 0x00,
        ];

        let pkt = Pkt::parse_ip(buf).unwrap();
        return pkt;
    }

    fn pkt_parse_2() -> Pkt {
        let buf = vec![
            // IPv4 Header
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, 17, 0x00, 0x00, 
            192, 168, 0, 1, 192, 168, 0, 2, 
            // UDP Header
            0x05, 0xd1, // source port
            0x19, 0x8e, // dport 6542
            0x00, 0x0d, // length (header + payload)
            0x00, 0x00,
            // Payload (5 bytes)
            0xde, 0xad, 0xbe, 0xef, 0xcd
        ];

        let pkt = Pkt::parse_ip(buf).unwrap();
        return pkt;
    }

    fn pkt_parse_3() -> Pkt {
        let buf = vec![
            // IPv4 Header
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, 17, 0x00, 0x00, 
            192, 168, 0, 1, 192, 168, 0, 2, 
            // UDP Header
            0x08, 0xd4, // source port
            0x15, 0x1f, // dport 5407
            0x00, 0x0a, // length (header + payload)
            0x00, 0x00,
            // Payload (2 bytes)
            0xff, 0x13
        ];

        let pkt = Pkt::parse_ip(buf).unwrap();
        return pkt;
    }

    fn pkt_parse_4() -> Pkt {
        let buf = vec![
            // IPv4 Header
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, 17, 0x00, 0x00, 
            192, 168, 0, 1, 192, 168, 0, 2, 
            // UDP Header
            0x08, 0xd1, // source port
            0x14, 0x1f, // dport 5151
            0x00, 0x0a, // length (header + payload)
            0x00, 0x00,
            // Payload (2 bytes)
            0xfc, 0x19
        ];

        let pkt = Pkt::parse_ip(buf).unwrap();
        return pkt;
    }


    #[test]
    fn test_rate_common_bucket() {
        let rate_bytes_per_sec = 6000;
        let duration_secs = 10.0;
        let start = Instant::now();

        let mut tp = TrafficPolicerCommonBucket::new(format!(
            "--max_len_bytes=18000 --rate_bytes_per_sec={}",
            rate_bytes_per_sec
        ))
        .unwrap();

        let pkt = pkt_parse_1();
        let mut dequeued = 0;

        while start.elapsed().as_secs_f64() < duration_secs {
            let _ = tp.enq(pkt.clone());
            if let Ok(Some(p)) = tp.deq() {
                dequeued += p.len();
            }
        }

        let elapsed_secs = start.elapsed().as_secs_f64();
        let actual_rate = dequeued as f64 / elapsed_secs;

        eprintln!(
            "\nDequeued {} bytes in {:.2} sec (rate: {:.2} Bps)",
            dequeued, elapsed_secs, actual_rate
        );

        assert!(
            (actual_rate >= 0.9 * rate_bytes_per_sec as f64)
                && (actual_rate <= 1.1 * rate_bytes_per_sec as f64),
            "Rate check failed: actual {:.2}, expected {}",
            actual_rate,
            rate_bytes_per_sec
        );
    }

    #[test]
    fn test_rate_multi_bucket_1() {
        let rate_bytes_per_sec = 6000;
        let duration_secs = 10.0;
        let start = Instant::now();

        let mut tp = TrafficPolicerMultiBucket::new(format!(
            "--max_len_bytes=18000 --rate_bytes_per_sec={} --num_flows=1 --dports=6542",
            rate_bytes_per_sec
        ))
        .unwrap();

        let pkt = pkt_parse_2();
        let mut dequeued = 0;

        while start.elapsed().as_secs_f64() < duration_secs {
            let _ = tp.enq(pkt.clone());
            if let Ok(Some(p)) = tp.deq() {
                dequeued += p.len();
            }
        }

        let elapsed_secs = start.elapsed().as_secs_f64();
        let actual_rate = dequeued as f64 / elapsed_secs;

        eprintln!(
            "\nDequeued {} bytes in {:.2} sec (rate: {:.2} Bps)",
            dequeued, elapsed_secs, actual_rate
        );

        assert!(
            (actual_rate >= 0.9 * rate_bytes_per_sec as f64)
                && (actual_rate <= 1.1 * rate_bytes_per_sec as f64),
            "Rate check failed: actual {:.2}, expected {}",
            actual_rate,
            rate_bytes_per_sec
        );
    }

    #[test]
    fn test_rate_multi_bucket_3() {
        let rate_bytes_per_sec = 6000;
        let duration_secs = 10.0;
        let start = Instant::now();

        let mut tp = TrafficPolicerMultiBucket::new(format!(
            "--max_len_bytes=18000 --rate_bytes_per_sec={} --num_flows=3 --dports=5678,6542,5407",
            rate_bytes_per_sec
        ))
        .unwrap();

        let pkt_options = [pkt_parse_1(), pkt_parse_2(), pkt_parse_3()];
        let mut rng = rand::thread_rng();
        let mut dequeued_5678 = 0;
        let mut dequeued_6542 = 0;
        let mut dequeued_5407 = 0;

        while start.elapsed().as_secs_f64() < duration_secs {
            let idx = rng.gen_range(0..pkt_options.len());
            let _ = tp.enq(pkt_options[idx].clone());
            if let Ok(Some(p)) = tp.deq() {
                if p.dport() == 5678 {
                    dequeued_5678 += p.len();
                } else if p.dport() == 6542 {
                    dequeued_6542 += p.len();
                } else if p.dport() == 5407 {
                    dequeued_5407 += p.len();
                }
            }
        }

        let elapsed_secs = start.elapsed().as_secs_f64();
        let rate_5678 = dequeued_5678 as f64 / elapsed_secs;
        let rate_6542 = dequeued_6542 as f64 / elapsed_secs;
        let rate_5407 = dequeued_5407 as f64 / elapsed_secs;

        eprintln!(
            "\n port 5678 dequeued {} bytes in {:.2} sec (rate: {:.2} Bps)
            \n port 6542 dequeued {} bytes in {:.2} sec (rate: {:.2} Bps)
            \n port 5407 dequeued {} bytes in {:.2} sec (rate: {:.2} Bps)",
            dequeued_5678, elapsed_secs, rate_5678,
            dequeued_6542, elapsed_secs, rate_6542,
            dequeued_5407, elapsed_secs, rate_5407
        );

        assert!(
            (rate_5678 >= 0.9 * (rate_bytes_per_sec / 3) as f64) 
                && (rate_5678 <= 1.1 * (rate_bytes_per_sec / 3) as f64),
            "port 5678 rate check failed: actual {:.2}, expected {}",
            rate_5678,
            rate_bytes_per_sec / 3
        );
        assert!(
            (rate_6542 >= 0.9 * (rate_bytes_per_sec / 3) as f64) 
                && (rate_6542 <= 1.1 * (rate_bytes_per_sec / 3) as f64),
            "port 6542 rate check failed: actual {:.2}, expected {}",
            rate_6542,
            rate_bytes_per_sec / 3
        );
        assert!(
            (rate_5407 >= 0.9 * (rate_bytes_per_sec / 3) as f64) 
                && (rate_5407 <= 1.1 * (rate_bytes_per_sec / 3) as f64),
            "port 5407 rate check failed: actual {:.2}, expected {}",
            rate_5407,
            rate_bytes_per_sec / 3
        );
    }

    #[test]
    fn test_rate_hybrid_1() {
        let rate_bytes_per_sec = 6000;
        let duration_secs = 10.0;
        let start = Instant::now();

        let mut tp = TrafficPolicerHybrid::new(format!(
            "--max_len_bytes=18000 --rate_bytes_per_sec={} --num_flows=1 --dports=6542",
            rate_bytes_per_sec
        ))
        .unwrap();

        let pkt = pkt_parse_2();
        let mut dequeued = 0;

        while start.elapsed().as_secs_f64() < duration_secs {
            let _ = tp.enq(pkt.clone());
            if let Ok(Some(p)) = tp.deq() {
                dequeued += p.len();
            }
        }

        let elapsed_secs = start.elapsed().as_secs_f64();
        let actual_rate = dequeued as f64 / elapsed_secs;

        eprintln!(
            "\nDequeued {} bytes in {:.2} sec (rate: {:.2} Bps)",
            dequeued, elapsed_secs, actual_rate
        );

        assert!(
            (actual_rate >= 0.9 * rate_bytes_per_sec as f64)
                && (actual_rate <= 1.1 * rate_bytes_per_sec as f64),
            "Rate check failed: actual {:.2}, expected {}",
            actual_rate,
            rate_bytes_per_sec
        );
    }

    #[test]
    fn test_rate_hybrid_2_equalpayload() {
        let rate_bytes_per_sec = 6000;
        let duration_secs = 10.0;
        let start = Instant::now();

        let mut tp = TrafficPolicerHybrid::new(format!(
            "--max_len_bytes=18000 --rate_bytes_per_sec={} --num_flows=2 --dports=5407,5151",
            rate_bytes_per_sec
        ))
        .unwrap();

        let pkt_options = [pkt_parse_3(), pkt_parse_4()];
        let mut rng = rand::thread_rng();
        let mut dequeued_5407 = 0;
        let mut dequeued_5151 = 0;

        while start.elapsed().as_secs_f64() < duration_secs {
            let idx = rng.gen_range(0..pkt_options.len());
            let _ = tp.enq(pkt_options[idx].clone());
            if let Ok(Some(p)) = tp.deq() {
                if p.dport() == 5407 {
                    dequeued_5407 += p.len();
                } else if p.dport() == 5151 {
                    dequeued_5151 += p.len();
                }
            }
        }

        let elapsed_secs = start.elapsed().as_secs_f64();
        let rate_5407 = dequeued_5407 as f64 / elapsed_secs;
        let rate_5151 = dequeued_5151 as f64 / elapsed_secs;

        eprintln!(
            "\n port 5407 dequeued {} bytes in {:.2} sec (rate: {:.2} Bps)
            \n port 5151 dequeued {} bytes in {:.2} sec (rate: {:.2} Bps)",
            dequeued_5407, elapsed_secs, rate_5407,
            dequeued_5151, elapsed_secs, rate_5151
        );

        // expect both flows to get approximately equal bandwidth since they have the same payload
        // so they have equal chance to get tokens from the default bucket
        assert!(
            (rate_5407 >= 0.9 * (rate_bytes_per_sec / 2) as f64) 
                && (rate_5407 <= 1.1 * (rate_bytes_per_sec / 2) as f64),
            "port 5407 rate check failed: actual {:.2}, expected {}",
            rate_5407,
            rate_bytes_per_sec / 2
        );
        assert!(
            (rate_5151 >= 0.9 * (rate_bytes_per_sec / 2) as f64) 
                && (rate_5151 <= 1.1 * (rate_bytes_per_sec / 2) as f64),
            "port 5151 rate check failed: actual {:.2}, expected {}",
            rate_5151,
            rate_bytes_per_sec / 2
        );
    }

    #[test]
    fn test_rate_hybrid_3() {
        let rate_bytes_per_sec = 6000;
        let duration_secs = 10.0;
        let start = Instant::now();

        let mut tp = TrafficPolicerHybrid::new(format!(
            "--max_len_bytes=18000 --rate_bytes_per_sec={} --num_flows=3 --dports=6542,5407,5678",
            rate_bytes_per_sec
        ))
        .unwrap();

        let pkt_options = [pkt_parse_1(), pkt_parse_2(), pkt_parse_3()];
        let mut rng = rand::thread_rng();
        let mut dequeued_5678 = 0;
        let mut dequeued_6542 = 0;
        let mut dequeued_5407 = 0;

        while start.elapsed().as_secs_f64() < duration_secs {
            let idx = rng.gen_range(0..pkt_options.len());
            let _ = tp.enq(pkt_options[idx].clone());
            if let Ok(Some(p)) = tp.deq() {
                if p.dport() == 5678 {
                    dequeued_5678 += p.len();
                } else if p.dport() == 6542 {
                    dequeued_6542 += p.len();
                } else if p.dport() == 5407 {
                    dequeued_5407 += p.len();
                }
            }
        }

        let elapsed_secs = start.elapsed().as_secs_f64();
        let rate_5678 = dequeued_5678 as f64 / elapsed_secs;
        let rate_6542 = dequeued_6542 as f64 / elapsed_secs;
        let rate_5407 = dequeued_5407 as f64 / elapsed_secs;

        eprintln!(
            "\n port 5678 dequeued {} bytes in {:.2} sec (rate: {:.2} Bps)
            \n port 6542 dequeued {} bytes in {:.2} sec (rate: {:.2} Bps)
            \n port 5407 dequeued {} bytes in {:.2} sec (rate: {:.2} Bps)",
            dequeued_5678, elapsed_secs, rate_5678,
            dequeued_6542, elapsed_secs, rate_6542,
            dequeued_5407, elapsed_secs, rate_5407
        );

        // Packet 5678 has no payload so we expect it to get nearly all the default bucket tokens, 
        // giving it around half the bandwidth. The other two flows need more tokens as they have 
        // larger payloads but 5678 always uses up the tokens before the bucket can fill up further,
        // so the other two flows are restricted to just their guaranteed bandwidth.
        assert!(
            (rate_5678 >= 0.9 * (rate_bytes_per_sec / 2) as f64) 
                && (rate_5678 <= 1.1 * (rate_bytes_per_sec / 2) as f64),
            "port 5678 rate check failed: actual {:.2}, expected {}",
            rate_5678,
            rate_bytes_per_sec / 2
        );
        assert!(
            (rate_6542 >= 0.9 * (rate_bytes_per_sec / 4) as f64) 
                && (rate_6542 <= 1.1 * (rate_bytes_per_sec / 4) as f64),
            "port 6542 rate check failed: actual {:.2}, expected {}",
            rate_6542,
            rate_bytes_per_sec / 4
        );
        assert!(
            (rate_5407 >= 0.9 * (rate_bytes_per_sec / 4) as f64) 
                && (rate_5407 <= 1.1 * (rate_bytes_per_sec / 4) as f64),
            "port 5407 rate check failed: actual {:.2}, expected {}",
            rate_5407,
            rate_bytes_per_sec / 4
        );
    }
}
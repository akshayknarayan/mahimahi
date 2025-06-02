use eyre::bail;
use eyre::Report;
use hwfq::{scheduler::htb::RateCounter, Pkt, Scheduler};
use quanta::Instant;
use std::collections::VecDeque;
use std::time::Duration;

#[derive(Debug)]
pub struct TokenBucket {
    rate_bytes_per_sec: usize,
    accum_bytes: f64,
    last_incr: Instant,
}

impl TokenBucket {
    pub fn new(rate_bytes_per_sec: usize) -> Self {
        Self {
            rate_bytes_per_sec,
            accum_bytes: 0.0,
            last_incr: Instant::now(),
        }
    }

    fn accumulate(&mut self) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_incr).as_secs_f64();
        self.accum_bytes += elapsed * (self.rate_bytes_per_sec as f64);
        let max_burst = (1514 * 10) as f64;
        if self.accum_bytes > max_burst {
            self.accum_bytes = max_burst;
        }
        self.last_incr = now;
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
        const ERR_STR: &str =
            "Tp takes two arguments: --max_len_bytes={value}, --rate_bytes_per_sec={value}";
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
        })
    }
}

impl<L: std::io::Write> Scheduler for TrafficPolicer<L> {
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        let tot_curr_len_bytes: usize = self.len_bytes();
        self.tb.accumulate();
        if p.len() > self.tb.accum_bytes as usize
            || p.len() + tot_curr_len_bytes > self.max_len_bytes
        {
            bail!(hwfq::Error::PacketDropped(p));
        }

        self.queue.push_back(p);

        Ok(())
    }

    fn deq(&mut self) -> Result<Option<Pkt>, Report> {
        self.tb.accumulate();
        match self.queue.front() {
            None => Ok(None),
            Some(p) if p.len() > self.tb.accum_bytes as usize => {
                Err(Report::msg("Dequeue failed: insufficient tokens"))
            }
            Some(p) => {
                self.tb.accum_bytes -= p.len() as f64;
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
        if let Some(p) = self.queue.front() {
            return p.len() > self.tb.accum_bytes as usize;
        }
        return true;
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

    fn pkt_parse() -> Pkt {
        let buf = vec![
            // IPv4 Header
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, 17, 0x00, 0x00, 192, 168, 0, 1, 192,
            168, 0, 2, // UDP Header
            0x04, 0xd2, 0x16, 0x2e, 0x00, 0x08, 0x00, 0x00,
        ];

        let pkt = Pkt::parse_ip(buf).unwrap();
        return pkt;
    }

    #[test]
    fn test_rate() {
        let rate_bytes_per_sec = 6000;
        let duration_secs = 10.0;
        let start = Instant::now();

        let mut tp = TrafficPolicer::new(format!(
            "--max_len_bytes=18000 --rate_bytes_per_sec={}",
            rate_bytes_per_sec
        ))
        .unwrap();

        let pkt = pkt_parse();
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
            "Rate check failed: actual {:.2}, expected ≈ {}",
            actual_rate,
            rate_bytes_per_sec
        );
    }
}

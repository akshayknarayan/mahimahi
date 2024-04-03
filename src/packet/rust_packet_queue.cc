#include "rust_packet_queue.hh"

RustPacketQueue::RustPacketQueue( const std::string & type_, const std::string & args_ )
  : type(type_),
    args(args_),
    inner_(make_rust_queue(type_, args_))
{
}

void RustPacketQueue::enqueue( QueuedPacket && p) {
    // need to translate from QueuedPacket to MahimahiQueuedPacket.
    // we do this by stripping off the 4-byte TUN header and saving
    // it separately, so that the packet parses as ipv4.
    uint32_t tun_header = *((uint32_t*) p.contents.substr(0, 4).data());
    auto contents = p.contents.erase(0, 4);
    auto mm_qp = MahimahiQueuedPacket {
        .arrival_time = p.arrival_time,
        .tun_header = tun_header,
        .payload = make_rust_vec(contents),
    };
    inner_->enqueue(mm_qp);
}

QueuedPacket RustPacketQueue::dequeue(void) {
    assert( not empty() );

    auto mm_qp = inner_->dequeue();
    std::string cont;
    make_cxx_string(mm_qp.payload, cont);

    // put the tun header back.
    char *s = (char*) &mm_qp.tun_header;
    cont.insert(0, s, 4);
    return QueuedPacket(cont, mm_qp.arrival_time);
}

bool RustPacketQueue::empty(void) const {
    return inner_->empty();
}

void RustPacketQueue::set_bdp( int bytes ) {
    inner_->set_bdp(bytes);
}
    
unsigned int RustPacketQueue::size_bytes( void ) const {
    return inner_->qsize_bytes();
}

unsigned int RustPacketQueue::size_packets( void ) const {
    return inner_->qsize_packets();
}


std::string RustPacketQueue::to_string( void ) const {
    std::string out;
    inner_->to_string(out);
    return out;
}

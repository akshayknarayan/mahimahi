#include "rust_packet_queue.hh"

RustPacketQueue::RustPacketQueue( const std::string & type_, const std::string & args_ )
  : type(type_),
    args(args_),
    inner_(make_rust_queue(type_, args_))
{
}

void RustPacketQueue::enqueue( QueuedPacket && p) {
    // need to translate from QueuedPacket to MahimahiQueuedPacket
    auto mm_qp = MahimahiQueuedPacket { .arrival_time = p.arrival_time, .payload = make_rust_vec(p.contents) };
    inner_->enqueue(mm_qp);
}

QueuedPacket RustPacketQueue::dequeue(void) {
    assert( not empty() );

    auto mm_qp = inner_->dequeue();
    std::string cont;
    make_cxx_string(mm_qp.payload, cont);
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

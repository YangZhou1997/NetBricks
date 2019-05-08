use super::{Batch, PacketError};
use packets::Packet;

/// Lazily-evaluated complete operator
///
/// Completes processing with a short-circuit error that simply emits the packet
pub struct CompleteBatch<B: Batch> {
    source: B
}

impl<B: Batch> CompleteBatch<B> {
    #[inline]
    pub fn new(source: B) -> Self {
        CompleteBatch { source }
    }
}

impl<B: Batch> Batch for CompleteBatch<B> {
    type Item = B::Item;

    #[inline]
    fn next(&mut self) -> Option<Result<Self::Item, PacketError>> {
        self.source.next().map(|item| match item {
            Ok(packet) => Err(PacketError::Complete(packet.mbuf())),
            e @ Err(_) => e,
        })
    }


    #[inline]
    fn receive(&mut self) {
        self.source.receive();
    }
}

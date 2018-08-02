# UDP2P
A P2P networking protocol based off of my P2PNet system, but implemented on top of UDP instead of TCP.

Currently features Kademlia-esque routing & UDP Packet payloads of 1024 bytes. 

Completely untested, tests & more features will hopefully be written over the next few weeks.

So far, the plan is to have the entire network fit into approx 2 threads, regardless of the num of peers.
One thread is the P2PSocket which handles broadcasting & sending messages, protocol messages & their responses, acknowledging received packets, rebroadcasting packets which haven't been acked, peerset management, & receiving messages.

The second thread, which I haven't even started writing yet, will disassemble data into packets to send & reassemble groups of packets into complete messages

I'd like to also somewhere integrate a bloom filter to hopefully prevent spam & messages from being repeatedly relayed. 
Here are some other things I'd like to include:
* Ban system
* PeerSet & Banlist Serialization & Saving
* Network sharding (Currently each packet has a networkId int that's being used for nothing. I'd like to either make it so that the Id somehow affects a node's interaction with peers of a different networkId, or to completely remove that field)
* Bloom filter to prevent nodes from self-spamming the network.
* Currently, peers have a "malicious" boolean associated with them. Put this to use, somehow.
* Message Relaying! Currently not implemented. However, may want to do this in the secondary thread; may be advantageous to grab a complete message instead of relaying individual packets.
* Important: Must put an upper limit on the number of retries for packets in the toAck queue. Potentially remove peers that have packets hitting that limit.

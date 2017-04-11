package classify;

import jpcap.packet.*;

public class ARP extends PacketClassify {

	private ARPPacket arp;

	public ARP() {
		layer = NETWORK_LAYER;
	}

	public boolean isBelong(Packet p) {
		return (p instanceof ARPPacket);
	}

	public String getProtocolName() {
		return "ARP/RARP";
	}

	public void analyze(Packet p) {
		data.clear();
		if (!isBelong(p))
			return;
		arp = (ARPPacket) p;
		data.add("Hardware Type: "+arp.hardtype);
		data.add("Protocol Type: "+arp.prototype);
		data.add("Hardware Address Length: "+arp.hlen);
		data.add("Protocol Address Length: "+arp.plen);
		data.add("Operation: "+arp.operation);
		data.add("Sender Hardware Address: "+arp.getSenderHardwareAddress());
		data.add("Sender Protocol Address: "+arp.getSenderProtocolAddress());
		data.add("Target Hardware Address: "+arp.getTargetHardwareAddress());
		data.add("Target Protocol Address: "+arp.getTargetProtocolAddress());
	}

}

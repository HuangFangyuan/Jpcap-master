package classify;

import jpcap.packet.*;

public class Ethernet extends PacketClassify{
		
	private EthernetPacket eth;

	public Ethernet(){
		layer=DATALINK_LAYER;
	}
	
	public boolean isBelong(Packet p){
		return (p.datalink!=null && p.datalink instanceof EthernetPacket);
	}

	public String getProtocolName(){
		return "Ethernet Frame";
	}

	public void analyze(Packet p){
		data.clear();
		if(!isBelong(p)) return;
		eth=(EthernetPacket)p.datalink;
		data.add("Frame Type: "+eth.frametype);
		data.add("Source MAC: "+eth.getSourceAddress());
		data.add("Destination MAC"+eth.getDestinationAddress());
	}



}

package classify;
import jpcap.packet.*;

public class UDP extends PacketClassify
{
	
	private UDPPacket udp;
	
	public UDP(){
		layer=TRANSPORT_LAYER;
	}
	
	public boolean isBelong(Packet p){
		return (p instanceof UDPPacket);
	}
	
	public String getProtocolName(){
		return "UDP";
	}
	
	public void analyze(Packet p){
		data.clear();
		if(!isBelong(p)) return;
		udp=(UDPPacket)p;
		data.add("Source Port: "+udp.src_port);
		data.add("Destination Port: "+udp.dst_port);
		data.add("Packet Length: "+udp.length);
	}
	
}

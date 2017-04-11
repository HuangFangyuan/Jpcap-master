package classify;
import jpcap.packet.*;

public class TCP extends PacketClassify
{
	
	public TCP(){
		layer=TRANSPORT_LAYER;
	}
	
	public boolean isBelong(Packet p){
		return (p instanceof TCPPacket);
	}
	
	public String getProtocolName(){
		return "TCP";
	}
	
	public void analyze(Packet p){
		data.clear();
		if(!isBelong(p)) return;
		TCPPacket tcp=(TCPPacket)p;
		data.add("Source Port: "+tcp.src_port);
		data.add("Destination Port: "+tcp.dst_port);
		data.add("Sequence Number: "+tcp.sequence);
		data.add("Ack Number: "+tcp.ack_num);
		data.add("URG Flag: "+tcp.urg);
		data.add("ACK Flag: "+tcp.ack);
		data.add("PSH Flag: "+tcp.psh);
		data.add("RST Flag: "+tcp.rst);
		data.add("SYN Flag: "+tcp.syn);
		data.add("FIN Flag: "+tcp.fin);
		data.add("Window Size: "+tcp.window);
	}
	
}

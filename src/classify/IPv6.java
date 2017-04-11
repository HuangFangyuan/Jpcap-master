package classify;
import jpcap.packet.*;

public class IPv6 extends PacketClassify{
	
	public IPv6(){
		layer=NETWORK_LAYER;
	}
	
	public boolean isBelong(Packet p){
		if(p instanceof IPPacket && ((IPPacket)p).version==6) return true;
		else return false;
	}
	
	public String getProtocolName(){
		return "IPv6";
	}
	
	public void analyze(Packet packet){
		data.clear();
		if(!isBelong(packet))	return;
		IPPacket ip=(IPPacket)packet;
		data.add("Version: 6");
		data.add("Class: "+ip.priority);
		data.add("Flow Label: "+ip.flow_label);
		data.add("Length: "+ip.length);
		data.add("Protocol: "+ip.protocol);
		data.add("Hop Limit: "+ip.hop_limit);
		data.add("Source IP: "+ip.src_ip.getHostAddress());
		data.add("Destination IP: "+ip.dst_ip.getHostAddress());
		data.add("Source Host Name: "+ip.src_ip.getHostName());
		data.add("Destination Host Name: "+ip.dst_ip.getHostName());
	}
	
}

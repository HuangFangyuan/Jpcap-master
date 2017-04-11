package classify;

import jpcap.packet.IPPacket;
import jpcap.packet.Packet;

public class IPv4 extends PacketClassify
{
	
	public IPv4(){
		layer=NETWORK_LAYER;
	}
	
	public boolean isBelong(Packet p){
		if(p instanceof IPPacket && ((IPPacket)p).version==4) return true;
		else return false;
	}
	
	public String getProtocolName(){
		return "IPv4";
	}
	
	public void analyze(Packet packet){
		data.clear();
		if(!isBelong(packet))	return;
		final IPPacket ip=(IPPacket)packet;
		data.add("Version: 4");
		data.add("Priority: "+ip.priority);
		data.add("Throughput: "+ip.t_flag);
		data.add("Reliability: "+ip.r_flag);
		data.add("Length: "+ip.length);
		data.add("Identification: "+ip.ident);
		data.add("Don't Fragment: "+ip.dont_frag);
		data.add("More Fragment: "+ip.more_frag);
		data.add("Fragment Offset: "+ip.offset);
		data.add("Time To Live: "+ip.hop_limit);
		data.add("Protocol: "+ip.protocol);
		data.add("Source IP: "+ip.src_ip.getHostAddress());
		data.add("Destination IP: "+ip.dst_ip.getHostAddress());
		data.add("Source Host Name: "+ip.src_ip.getHostName());
		data.add("Destination Host Name: "+ip.dst_ip.getHostName());
	}
	
}

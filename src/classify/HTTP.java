package classify;

import jpcap.packet.*;
import java.io.*;

public class HTTP extends PacketClassify {
	
	public HTTP() {
		layer = APPLICATION_LAYER;
	}

	public boolean isBelong(Packet p) {
		try {
			if (p instanceof TCPPacket && (((TCPPacket) p).src_port == 80 || ((TCPPacket) p).dst_port == 80)) {

				BufferedReader in = new BufferedReader(new StringReader(new String(p.data)));
				String method;
				method = in.readLine();
				if (method == null || method.indexOf("HTTP") == -1) {
					// this packet doesn't contain HTTP header
					method = "Not HTTP Header";
					return false;
				} else
					return true;
			} else
				return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;

		}
	}

	public String getProtocolName() {
		return "HTTP";
	}

	public void analyze(Packet p) {
		data.clear();
		if (!isBelong(p))
			return;
		try {
			BufferedReader in = new BufferedReader(new StringReader(new String(p.data)));

			String l;
			// read headers
			while (true) {
				if ((l = in.readLine()).length() > 0) {
					data.add(l);
				}
				if ((l = in.readLine()).length() > 0) {
					data.add(l);
				}
				else
					break;
			}
		} catch (Exception e) {
		}
	}

}

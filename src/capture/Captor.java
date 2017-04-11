package capture;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import jpcap.*;
import jpcap.packet.*;

import classify.*;

public class Captor {

	private long MAX = 10000;
	private NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	private List<Packet> packets = new ArrayList<>();
	private JpcapCaptor jpcap = null;
	private boolean isLive;
	private Thread captureThread;
	boolean isFilter = false;

	//获取Packets
	public List<Packet> getPackets() {
		return packets;
	}

	//获取jpcap
	//无用
	public JpcapCaptor getJpcap() {
		return jpcap;
	}

	//获取网卡列表 
	public String[] showDevice() {
		if (devices == null) {
			//System.out.println("No device found.");
			return null;
		} else {
			String[] names = new String[devices.length];
			for (int i = 0; i < names.length; i++) {
				names[i] = (devices[i].description == null ? devices[i].name : devices[i].description);
				//System.out.println(names[i]);
			}
			return names;
		}
	}

	//显示数据包完整信息
	public String showPacket(Packet p) {
		byte[] bytes = new byte[p.header.length + p.data.length];

		System.arraycopy(p.header, 0, bytes, 0, p.header.length);
		System.arraycopy(p.data, 0, bytes, p.header.length, p.data.length);

		StringBuffer buf = new StringBuffer();
		for (int i = 0, j; i < bytes.length;) {
			for (j = 0; j < 8 && i < bytes.length; j++, i++) {
				String d = Integer.toHexString((int) (bytes[i] & 0xff));
				buf.append((d.length() == 1 ? "0" + d : d) + " ");
				if (bytes[i] < 32 || bytes[i] > 126)
					bytes[i] = 46;
			}
			buf.append("[" + new String(bytes, i - j, j) + "]\n");
		}
		return buf.toString();
	}

	//设置过滤器
	public void setFilter(String s) {
		try {
			if(s.equals("http")||s.equals("HTTP")){
				isFilter = true;
			}else{
				jpcap.setFilter(s, true);
			}

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	//选择网卡
	public void chooseDevice(int i) {
		try {
			jpcap = JpcapCaptor.openDevice(devices[i], 1514, true, 50);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	//开始捕获数据包
	public void capturePackets() {
		if (jpcap != null) {
			isLive = true;
			startCaptureThread();
		}
	}

	private void startCaptureThread() {
		if (captureThread != null)
			return;

		captureThread = new Thread(new Runnable() {
			public void run() {
				while (captureThread != null) {
					if (jpcap.processPacket(1, handler) == 0 && !isLive)
						stopCaptureThread();
					Thread.yield();
				}
				jpcap.breakLoop();
			}
		});
		captureThread.setPriority(Thread.MIN_PRIORITY);
		captureThread.start();
	}

	//停止捕获数据包
	public void stopCaptureThread() {
		captureThread = null;
	}

	//对每个捕获的数据包进行处理
	private PacketReceiver handler = new PacketReceiver() {
		public void receivePacket(final Packet packet) {	
			if (isFilter) {
				HTTP http = new HTTP();
				if(http.isBelong(packet)){
					packets.add(packet);
				}
			}else{
				packets.add(packet);
			}
			while (packets.size() > MAX) {
				packets.remove(0);
			}
		}
	};
}
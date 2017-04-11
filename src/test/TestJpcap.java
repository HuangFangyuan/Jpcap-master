package test;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;
import jpcap.packet.Packet;

import capture.*;

public class TestJpcap {
	public static void main(String[] args) throws InterruptedException {

////		example:
////		如何获取每个数据包的详细信息
//		Analyse analyse = new Analyse(); 
//		analyse.startClassify(packet);
//		LinkedHashMap<String, ArrayList<String>> info = analyse.getInfo();
//		for(Iterator it = info.entrySet().iterator();it.hasNext();){  
//			Entry<String, ArrayList<String>> entry = (Entry<String, ArrayList<String>>) it.next();
//			System.out.println(entry.getKey());
//			ArrayList<String> arrayList = entry.getValue();
//			for (String s : arrayList) {
//				System.out.println("  "+s);
//			}
//		}
		
		
//		Captor captor = new Captor(); // 初始化Captor对象
//		String[] device = captor.showDevice(); //显示网卡列表
//		for(String s:device){
//			System.out.println(s);
//		}
//		captor.chooseDevice(4); //选择网卡
//	//	captor.setFilter("tcp"); //设置过滤器
//		captor.capturePackets(); //开始捕获
//		while(true){
//		//	System.out.println("进入循环");
//			Thread.sleep(1000);
//			List<Packet> packets = captor.getPackets();
//			System.out.println(packets.size());
//			if(!packets.isEmpty())
//				System.out.println(captor.showPacket(packets.get(0)));
//		}
		
//		captor.stopCaptureThread(); //停止捕获
		
	}
}

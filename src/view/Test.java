package view;

import javax.swing.JFrame;
import javax.swing.JButton;
import javax.swing.JComboBox;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Vector;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import capture.Analyse;
import capture.Captor;
import jpcap.packet.Packet;

import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.JTree;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JLabel;

public class Test extends JFrame {
	private JTable table;
	private JTree tree;
	private JTextArea textArea;
	boolean flag = true;
	boolean flag1 = true;
	List<Packet> packets;
	List<Packet> result = new ArrayList<>();
	Captor capotor = new Captor();
	int i = 0;
	private JTextField textField;
	
	public Test(){
		
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(600,400,675,369);
		this.getContentPane().setLayout(null);
		
		//表格部分
		Vector<String> columnNames = new Vector<String>();//{"编号","时间","长度","原MAC地址","目的MAC地址","协议","源IP地址","目的IP地址"};
		Vector<String> data =new Vector<>();
		columnNames.add("编号");
		columnNames.add("时间");
		columnNames.add("长度");
		columnNames.add("原MAC地址");
		columnNames.add("目的MAC地址");
		columnNames.add("协议");
		columnNames.add("源IP地址");
		columnNames.add("目的IP地址");

		table = new JTable(new DefaultTableModel(data,columnNames)
		{
			@Override
			public boolean isCellEditable(int row,int column){  
				return false;  
            }   
		}
			);
		table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			
			@Override
			public void valueChanged(ListSelectionEvent e) {
				i++;
				System.out.println(i);
				new Thread(new Runnable(){
					@Override
					public void run(){
						EventQueue.invokeLater(new Runnable(){
							public void run(){
								if(flag1){
									int index = table.getSelectedRow();
									Packet packet = result.get(index);
									Analyse analyse = new Analyse(); 
									analyse.startClassify(packet);
									LinkedHashMap<String, ArrayList<String>> info = analyse.getInfo();
									DefaultMutableTreeNode top = new DefaultMutableTreeNode("第"+(index+1)+"个数据包");
									for(Iterator it = info.entrySet().iterator();it.hasNext();){  
										Entry<String, ArrayList<String>> entry = (Entry<String, ArrayList<String>>) it.next();
										System.out.println(entry.getKey());
										ArrayList<String> arrayList = entry.getValue();
//										DefaultMutableTreeNode node = new DefaultMutableTreeNode(entry.getKey());
										top.add(new DefaultMutableTreeNode(entry.getKey()+":"));
										for (String s : arrayList) {
											top.add(new DefaultMutableTreeNode(s));
										}
//										top.add(new DefaultMutableTreeNode(node));
									}
									DefaultTreeModel treeModel = new DefaultTreeModel(top);
									tree.setModel(treeModel);
									textArea.setText(capotor.showPacket(packet));	
								}
							}
						});
//						if(flag1 == true){
//							int index = table.getSelectedRow();
//							Packet packet = result.get(index);
//							Analyse analyse = new Analyse(); 
//							analyse.startClassify(packet);
//							LinkedHashMap<String, ArrayList<String>> info = analyse.getInfo();
//							DefaultMutableTreeNode top = new DefaultMutableTreeNode("第"+(index+1)+"个数据包");
//							for(Iterator it = info.entrySet().iterator();it.hasNext();){  
//								Entry<String, ArrayList<String>> entry = (Entry<String, ArrayList<String>>) it.next();
//								System.out.println(entry.getKey());
//								ArrayList<String> arrayList = entry.getValue();
////								DefaultMutableTreeNode node = new DefaultMutableTreeNode(entry.getKey());
//								top.add(new DefaultMutableTreeNode(entry.getKey()+":"));
//								for (String s : arrayList) {
//									top.add(new DefaultMutableTreeNode(s));
//								}
////								top.add(new DefaultMutableTreeNode(node));
//							}
//							DefaultTreeModel treeModel = new DefaultTreeModel(top);
//							tree.setModel(treeModel);
//							textArea.setText(capotor.showPacket(packet));	
//						}
					}
				}).start();
			}
		});
		table.setBounds(22, 42, 356, 179);
		JScrollPane scrollPane = new JScrollPane(table);
		scrollPane.setBounds(22, 42, 616, 114);
		getContentPane().add(scrollPane);
		//选择网卡
		String[] deviceList = capotor.showDevice();
		JComboBox comboBox = new JComboBox(deviceList);
		comboBox.setBounds(22, 11, 200, 22);
		getContentPane().add(comboBox);
		
//		String[] list1 = {"过滤规则（可选择）","ARP"};
//		JComboBox comboBox_1 = new JComboBox(list1);
//		comboBox_1.setBounds(241, 11, 144, 23);
//		getContentPane().add(comboBox_1);
		
		textField = new JTextField();
		textField.setBounds(305, 11, 66, 21);
		getContentPane().add(textField);
		textField.setColumns(10);
		
		//按钮
		JButton btnNewButton = new JButton("开始");
		btnNewButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) {
				flag1 =true;
				flag = true;
				String choosenDevice = comboBox.getSelectedItem().toString();
				for(int i=0;i<deviceList.length;i++){
					if(deviceList[i].equals(choosenDevice)){
						capotor.chooseDevice(i);
						break;
					}
				}
				String protocol;
				protocol = textField.getText();
				System.out.println(protocol);
				capotor.capturePackets();
				Analyse analyse = new Analyse(); 
				Packet packet;
				String[] info;
				int count = 0;
				int num = 0;
				new Thread(new Runnable(){
					@Override
					public void run(){
						String choosenDevice = comboBox.getSelectedItem().toString();
						for(int i=0;i<deviceList.length;i++){
							if(deviceList[i] == choosenDevice){
								capotor.chooseDevice(i);
								break;
							}
						}
						String protocol = "";
						protocol = textField.getText().toString();
						System.out.println(protocol);
						capotor.capturePackets();
						Analyse analyse = new Analyse(); 
						Packet packet;
						String[] info;
						int count = 0;
						int num = 0;
						//循环添加行
					
						while(flag){
							System.out.println("jinru");
							packets = capotor.getPackets();
							if(packets.size()>count){
								packet = packets.get(count++);
								info = analyse.getInfo(packet);
								if(protocol.equals(info[4])){
									result.add(packet);
									Vector row = new Vector();
									row.add(++num);
									row.add(info[0]);
									row.add(info[1]);
									row.add(info[2]);
									row.add(info[3]);
									row.add(info[4]);
									row.add(info[5]);
									row.add(info[6]);
									((DefaultTableModel)table.getModel()).addRow(row);
								}	
								else if(protocol.length()<1){
									result.add(packet);
									Vector row = new Vector();
									row.add(++num);
									row.add(info[0]);
									row.add(info[1]);
									row.add(info[2]);
									row.add(info[3]);
									row.add(info[4]);
									row.add(info[5]);
									row.add(info[6]);
									((DefaultTableModel)table.getModel()).addRow(row);
								}
							}
						}
					}
				}).start();
				
			}
		});
		btnNewButton.setBounds(395, 11, 71, 22);
		getContentPane().add(btnNewButton);
		
		JButton btnNewButton_1 = new JButton("取消");
		btnNewButton_1.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) {
				flag = false;
				capotor.stopCaptureThread();
			}
		});
		btnNewButton_1.setBounds(476, 11, 71, 22);
		getContentPane().add(btnNewButton_1);
		
		//信息栏
		textArea = new JTextArea();
		textArea.setBounds(220, 181, 402, 138);
		textArea.setEditable(false);
		JScrollPane scrollPane_2 = new JScrollPane(textArea);
		scrollPane_2.setBounds(220, 181, 402, 139);
		getContentPane().add(scrollPane_2);
		
		//信息树
		DefaultMutableTreeNode initial =null;
		tree = new JTree(initial);
		tree.setBounds(22, 181, 168, 138);
		JScrollPane scrollPane_1 = new JScrollPane(tree);
		scrollPane_1.setBounds(22, 181, 168, 138);
		getContentPane().add(scrollPane_1);
		
		//清空按钮
		JButton button = new JButton("清空");
		button.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				packets.clear();
				result.clear();
				flag = false;
				flag1 = false;
				textArea.setText(null);
				DefaultTreeModel treeModel = new DefaultTreeModel(null);
				tree.setModel(treeModel);
				DefaultTableModel tableModel =(DefaultTableModel) table.getModel();
//				int count=tableModel.getRowCount()-1;	
//				for(int i=count;i>=0;i--){
//					tableModel.removeRow(i);
//				}
				tableModel.setRowCount(0);
			}
		});
		button.setBounds(557, 11, 65, 22);
		getContentPane().add(button);
		
		JLabel lblNewLabel = new JLabel("过滤规则");
		lblNewLabel.setBounds(241, 15, 54, 15);
		getContentPane().add(lblNewLabel);
		
		
		
	
			
		
	}
	
	
	public static void main(String[] args) {
		new Test().setVisible(true);
	}
}

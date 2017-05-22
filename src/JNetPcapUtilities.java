import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;


public class JNetPcapUtilities {

	public static byte[] getMACBytes(String macString) {
		String[] bytes = macString.split(":");
        byte[] parsed = new byte[bytes.length];

        for (int x = 0; x < bytes.length; x++)
        {
            BigInteger temp = new BigInteger(bytes[x], 16);
            byte[] raw = temp.toByteArray();
            parsed[x] = raw[raw.length - 1];
        }
        return parsed;
	}
	
	public static byte[] getIPBytes(String ipv4String) {
		try {
			InetAddress ip = InetAddress.getByName(ipv4String);
			return ip.getAddress();
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
	}

	private static int u(byte b) {
		return (b >= 0) ? b : b + 256;
	}
	
	public static String getIPFromBytes(byte[] ipv4) {
		return u(ipv4[0]) + "." + u(ipv4[1]) + "." + u(ipv4[2]) + "." + u(ipv4[3]);
	}
	
	public static String getMacFromBytes(byte[] mac) {
		final StringBuilder buf = new StringBuilder();
		for (byte b : mac) {
			if (buf.length() != 0) {
				buf.append(':');
			}
			if (b >= 0 && b < 16) {
				buf.append('0');
			}
			buf.append(Integer.toHexString((b < 0) ? b + 256 : b));
		}
		return buf.toString();
	}
	
	public static JPacket getICMPPaket(byte[] srcMac, byte[] dstMac, byte[] srcIP, byte[] dstIP, short idIP, byte ttl, byte icmpType, byte icmpCode, byte icmpId, byte icmpSequence) {
		String data ="002369f4b789 24770324d24c 0800 " + // ciel MAC 00:23:69:74:b7:89, zdroj MAC 24:77:03:24:d2:4c, dalsia hlavicka je IP 0800
				"4 5 00 003c 1ddb 0000 80 01 186f 02000077 02000001 " + 
				//IPv4, dlzka hlavicky 5, type of service 0, dlzka paketu 60 (20 hlavicka + 8 ICMP + 32 data), id paketu 1ddb, fragmentacia nie je 0000
				//80 = time to live 128, dalsia hlavicka je ICMP 01, checksum 186f, zdrojova IP 2.0.0.119, cielova IP 2.0.0.1
				"08 00 4d56 0001 0005 " + //ICMP type 8, code 0 teda echo request, checksum 4d56, identifikator sekvencie 1, poradie 5 
				"6162636465666768696a6b6c6d6e6f7071727374757677616263646566676869"; //data
		
		JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, data);
		Ethernet ethHeader = packet.getHeader(new Ethernet());
		ethHeader.destination(dstMac);
		ethHeader.source(srcMac);
		Ip4 ipHeader = packet.getHeader(new Ip4());
		ipHeader.source(srcIP);
		ipHeader.destination(dstIP);
		ipHeader.id(idIP);
		ipHeader.ttl(ttl);
		ipHeader.checksum(ipHeader.calculateChecksum());
		Icmp icmpHeader = packet.getHeader(new Icmp());
		
		icmpHeader.setByte(0, icmpType);
		icmpHeader.setByte(1, icmpCode);
		icmpHeader.setByte(5, icmpId);
		icmpHeader.setByte(7, icmpSequence);
		short cs = (short) icmpHeader.calculateChecksum();
		ByteBuffer bb = ByteBuffer.allocate(2);
		bb.putShort(cs);
		byte[] pole = bb.array();
		icmpHeader.setByteArray(2, pole);
		return packet;
	}

	public static JPacket getICMPPaket(String srcMac, String dstMac, String srcIP, String dstIP, int idIP, int ttl, int icmpType, int icmpCode, int icmpId, int icmpSequence) {
		return getICMPPaket(getMACBytes(srcMac), getMACBytes(dstMac), getIPBytes(srcIP), getIPBytes(dstIP), (short) idIP, (byte) ttl, (byte) icmpType, (byte) icmpCode, (byte) icmpId, (byte) icmpSequence);
	}
	
	public static JPacket getARPPaket(byte[] srcMac, byte[] dstMac, boolean request, byte[] senderMac, byte[] senderIP, byte[] targetMac, byte[] targetIP) {
		String data ="ffffffffffff 24770324d24c 0806" + // ciel MAC FF:FF:FF:FF:FF:FF, zdroj MAC 24:77:03:24:d2:4c, dalsia hlavicka je ARP 0806
				"0001 0800 06 04 0001" + //ethernet 0001, pre IPv4 0800, velkost MAC 6, velkost IP 4, poziadavka 0001 (odpoved je 0002)
				"24770324d24c" + //sender MAC
				"02000077" + // sender IP 2.0.0.119
				"000000000000" + //target MAC
				"02000005"; //target IP
		
		JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, data);
		Ethernet ethHeader = packet.getHeader(new Ethernet());
		ethHeader.destination(dstMac);
		ethHeader.source(srcMac);
		Arp arpHeader = packet.getHeader(new Arp());
		if (! request)
			arpHeader.setByte(7, (byte) 2);
		arpHeader.setByteArray(8, senderMac);
		arpHeader.setByteArray(14, senderIP);
		arpHeader.setByteArray(18, targetMac);
		arpHeader.setByteArray(24, targetIP);
		return packet;
	}

	public static JPacket getARPPaket(String srcMac, String dstMac, boolean request, String senderMac, String senderIP, String targetMac, String targetIP) {
		return getARPPaket(getMACBytes(srcMac), getMACBytes(dstMac), request, getMACBytes(senderMac), getIPBytes(senderIP), getMACBytes(targetMac), getIPBytes(targetIP));
	}
	
	public static JPacket getUDPPacket(byte[] srcMac, byte[] dstMac, byte[] srcIP, byte[] dstIP, short idIP, byte ttl, short srcPort, short dstPort) {
		String data = "002369f4b789 24770324d24c 0800" + // ciel MAC 00:23:69:74:b7:89, zdroj MAC 24:77:03:24:d2:4c, dalsia hlavicka je IP 0800
				"4 5 00 003f 5a18 0000 80 11 7d43 02000077 58d40808" +
				//IPv4, dlzka hlavicky 5, type of service 0, dlzka paketu 63 (20 hlavicka IP + 16 UDP + 27 data), id paketu 5a18, fragmentacia nie je 0000
				//80 = time to live 128, dalsia hlavicka je UDP 11, checksum 7d43, zdrojova IP 2.0.0.119, cielova IP 88.212.8.8
				"d8f0 0035 002b 5d6f" + // srcPort 55536, dstPort 53, dlzka 43, checksum 5d6f
				"432f01000001000000000000037777770a6d6f6472796b6f6e696b02736b0000010001"; //data (DNS request - nespracuvavame)
		JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, data);
		Ethernet ethHeader = packet.getHeader(new Ethernet());
		ethHeader.destination(dstMac);
		ethHeader.source(srcMac);
		Ip4 ipHeader = packet.getHeader(new Ip4());
		ipHeader.source(srcIP);
		ipHeader.destination(dstIP);
		ipHeader.id(idIP);
		ipHeader.ttl(ttl);
		ipHeader.checksum(ipHeader.calculateChecksum());
		Udp udpHeader = packet.getHeader(new Udp());
		udpHeader.source(srcPort);
		udpHeader.destination(dstPort);
		udpHeader.checksum(udpHeader.calculateChecksum());
		return packet;
	}

	public static JPacket getUDPPacket(String srcMac, String dstMac, String srcIP, String dstIP, int idIP, int ttl, int srcPort, int dstPort) {
		return getUDPPacket(getMACBytes(srcMac), getMACBytes(dstMac), getIPBytes(srcIP), getIPBytes(dstIP), (short) idIP, (byte) ttl, (short) srcPort, (short) dstPort);
	}

	public static JPacket getTCPSynPacket(byte[] srcMac, byte[] dstMac, byte[] srcIP, byte[] dstIP, short idIP, byte ttl, short srcPort, short dstPort) {		
		String data = "002369f4b789 24770324d24c 0800" + // ciel MAC 00:23:69:74:b7:89, zdroj MAC 24:77:03:24:d2:4c, dalsia hlavicka je IP 0800
				"4 5 00 0034 5a1a 4000 80 06 f8d5 02000077 5db847a5" +
				//IPv4, dlzka hlavicky 5, type of service 0, dlzka paketu 52, id paketu 5a1a, fragmentacia je zakazana 4000
				//80 = time to live 128, dalsia hlavicka je TCP 06, checksum f8d5, zdrojova IP 2.0.0.119, cielova IP 93.184.71.165
				"c353 0050 013f543d 00000000" + //srcPort 50003, dstPort 80, sequenceNumber 20927549, ACKNumber 0
				"8002 2000 8e22 " + // dlzka hlavicky 8*4=32, SYN nastavene na 1, window 8192, checksum 8e22
				"0000020405b40103030201010402"; //options MSS 1460, NOP, WSCALE 2
		JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, data);
		Ethernet ethHeader = packet.getHeader(new Ethernet());
		ethHeader.destination(dstMac);
		ethHeader.source(srcMac);
		Ip4 ipHeader = packet.getHeader(new Ip4());
		ipHeader.source(srcIP);
		ipHeader.destination(dstIP);
		ipHeader.id(idIP);
		ipHeader.ttl(ttl);
		ipHeader.checksum(ipHeader.calculateChecksum());
		Tcp tcpHeader = packet.getHeader(new Tcp());
		tcpHeader.source(srcPort);
		tcpHeader.destination(dstPort);
		tcpHeader.checksum(tcpHeader.calculateChecksum());
		return packet;
	}

	public static JPacket getTCPSynPacket(String srcMac, String dstMac, String srcIP, String dstIP, int idIP, int ttl, int srcPort, int dstPort) {		
		return getTCPSynPacket(getMACBytes(srcMac), getMACBytes(dstMac), getIPBytes(srcIP), getIPBytes(dstIP), (short) idIP, (byte) ttl, (short) srcPort, (short) dstPort);
	}
	
	public static void main(String[] args) {
//		System.out.println(getARPPaket("24:77:03:24:d2:4c", "ff:ff:ff:ff:ff:ff", true, "24:77:03:24:d2:4c", "2.0.0.1", "00:00:00:00:00:00", "2.0.0.119"));
//		getICMPPaket(getMACBytes("24:77:03:24:d2:4c"), getMACBytes("20:07:73:24:d2:4c"), getIPBytes("1.128.64.254"), getIPBytes("1.2.3.4"), (short) 7864, (byte) 50, (byte) 0, (byte) 0, (byte) 5, (byte) 1);
//		System.out.println(getUDPPacket("24:77:03:24:d2:4c", "20:07:73:24:d2:4c", "1.128.64.254", "1.2.3.4", 7864, 50, 4315, 111));
		System.out.println(getTCPSynPacket("24:77:03:24:d2:4c", "20:07:73:24:d2:4c", "1.128.64.254", "1.2.3.4", 7864, 50, 4315, 111));
	}
}

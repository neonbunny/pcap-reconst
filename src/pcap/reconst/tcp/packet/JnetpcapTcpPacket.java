package pcap.reconst.tcp.packet;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class JnetpcapTcpPacket implements TcpPacket {
	private Ip4 ipPacket;
	private Tcp tcpPacket;
	private PcapHeader pcapHeader;

	public JnetpcapTcpPacket(PcapHeader pcap, Ip4 ip, Tcp tcp) {
		this.pcapHeader = pcap;
		this.ipPacket = ip;
		this.tcpPacket = tcp;
	}

	public InetAddress getSourceIP() {
		try {
			return Inet4Address.getByAddress(ipPacket.source());
		}
		catch (UnknownHostException uhe) {
			uhe.printStackTrace();
			return null;
		}
	}

	public int getSourcePort() {
		return tcpPacket.source();
	}

	public InetAddress getDestinationIP() {
		try {
			return Inet4Address.getByAddress(ipPacket.destination());
		}
		catch (UnknownHostException uhe) {
			uhe.printStackTrace();
			return null;
		}
	}

	public int getDestinationPort() {
		return tcpPacket.destination();
	}

	public int getCaptureLength() {
		return pcapHeader.caplen();
	}

	public int getLength() {
		return pcapHeader.wirelen();
	}

	public int getHeaderLength() {
		//Appears to be a total of all headers prior to the data
		return tcpPacket.getPayloadOffset();
	}

	public int getDataLength() {
		return tcpPacket.getPayloadLength();
	}

	public long getSequence() {
		return tcpPacket.seq();
	}

	public long getAckNum() {
		return tcpPacket.ack();
	}

	public byte[] getData() {
		return tcpPacket.getPayload();
	}

	public boolean getSyn() {
		return tcpPacket.flags_SYN();
	}

	public boolean getAck() {
		return tcpPacket.flags_ACK();
	}

	public boolean getFin() {
		return tcpPacket.flags_FIN();
	}

	public boolean getPsh() {
		return tcpPacket.flags_PSH();
	}

	public long getTimestampSec() {
		return pcapHeader.seconds();
	}

	public long getTimestampUSec() {
		return pcapHeader.nanos() / 1000;
	}

	public String toString() {
		return new ToStringBuilder(this)
			.append("Source IP", getSourceIP())
			.append("Source Port", getSourcePort())
			.append("Destination IP", getDestinationIP())
			.append("Destination Port", getDestinationPort())
			.append("Capture Length", getCaptureLength())
			.append("Length", getLength())
			.append("Header Length", getHeaderLength())
			.append("Data Length", getDataLength())
			.append("Sequence", getSequence())
			.append("Ack Num", getAckNum())
			.append("Data", getData())
			.append("Syn", getSyn())
			.append("Ack", getAck())
			.append("Fin", getFin())
			.append("Psh", getPsh())
			.append("Timestamp Sec", getTimestampSec())
			.append("Timestamp USec", getTimestampUSec())
			.toString();
	}
}

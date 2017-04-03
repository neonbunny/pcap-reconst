package pcap.reconst.tcp.packet;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class JnetpcapTcpPacket extends AbstractTcpPacket {
	private InetAddress sourceIp;
	private int sourcePort;
	private InetAddress destinationIp;
	private int destinationPort;
	private int captureLength;
	private int length;
	private int headerLength;
	private int dataLength;
	private long sequence;
	private long ackNumber;
	private byte[] data;
	private boolean syn;
	private boolean ack;
	private boolean fin;
	private boolean psh;
	private long timestampSec;
	private long timestampUSec;
	
	public JnetpcapTcpPacket(PcapHeader pcapHeader, Ip4 ipPacket, Tcp tcpPacket) {
		try {
			sourceIp = Inet4Address.getByAddress(ipPacket.source());
			destinationIp = Inet4Address.getByAddress(ipPacket.destination());
		}
		catch (UnknownHostException uhe) {
			uhe.printStackTrace();
		}
		sourcePort = tcpPacket.source();
		destinationPort = tcpPacket.destination();
		captureLength = pcapHeader.caplen();
		length = pcapHeader.wirelen();
		headerLength = tcpPacket.getPayloadOffset();
		dataLength = tcpPacket.getPayloadLength();
		sequence = tcpPacket.seq();
		ackNumber = tcpPacket.ack();
		data = tcpPacket.getPayload();
		syn = tcpPacket.flags_SYN();
		ack = tcpPacket.flags_ACK();
		fin = tcpPacket.flags_FIN();
		psh = tcpPacket.flags_PSH();
		timestampSec = pcapHeader.seconds();
		timestampUSec = pcapHeader.nanos() / 1000;
	}

	public InetAddress getSourceIP() {
		return sourceIp;
	}

	public int getSourcePort() {
		return sourcePort;
	}

	public InetAddress getDestinationIP() {
		return destinationIp;
	}

	public int getDestinationPort() {
		return destinationPort;
	}

	public int getCaptureLength() {
		return captureLength;
	}

	public int getLength() {
		return length;
	}

	public int getHeaderLength() {
		//Appears to be a total of all headers prior to the data
		return headerLength;
	}

	public int getDataLength() {
		return dataLength;
	}

	public long getSequence() {
		return sequence;
	}

	public long getAckNum() {
		return ackNumber;
	}

	public byte[] getData() {
		return data;
	}

	public boolean getSyn() {
		return syn;
	}

	public boolean getAck() {
		return ack;
	}

	public boolean getFin() {
		return fin;
	}

	public boolean getPsh() {
		return psh;
	}

	public long getTimestampSec() {
		return timestampSec;
	}

	public long getTimestampUSec() {
		return timestampUSec;
	}
}

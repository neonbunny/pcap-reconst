/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.tcp.packet;

import java.net.InetAddress;

import jpcap.packet.TCPPacket;

import org.apache.commons.lang3.builder.ToStringBuilder;

public class JpcapTcpPacket extends AbstractTcpPacket {
	private TCPPacket tcpPacket;

	public JpcapTcpPacket(TCPPacket tcpPacket) {
		this.tcpPacket = tcpPacket;
	}

	public InetAddress getSourceIP() {
		return tcpPacket.src_ip;
	}

	public int getSourcePort() {
		return tcpPacket.src_port;
	}

	public InetAddress getDestinationIP() {
		return tcpPacket.dst_ip;
	}

	public int getDestinationPort() {
		return tcpPacket.dst_port;
	}

	public int getCaptureLength() {
		return tcpPacket.caplen;
	}

	public int getLength() {
		return tcpPacket.len;
	}

	public int getHeaderLength() {
		return tcpPacket.header.length;
	}

	public int getDataLength() {
		return tcpPacket.data.length;
	}

	public long getSequence() {
		return tcpPacket.sequence;
	}

	public long getAckNum() {
		return tcpPacket.ack_num;
	}

	public byte[] getData() {
		return tcpPacket.data;
	}

	public boolean getSyn() {
		return tcpPacket.syn;
	}

	public boolean getAck() {
		return tcpPacket.ack;
	}

	public boolean getFin() {
		return tcpPacket.fin;
	}

	public boolean getPsh() {
		return tcpPacket.psh;
	}

	public long getTimestampSec() {
		return tcpPacket.sec;
	}

	public long getTimestampUSec() {
		return tcpPacket.usec;
	}
}

package pcap.reconst.tcp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import pcap.reconst.tcp.packet.JnetpcapTcpPacket;

public class JnetpcapPacketProcessor<T> implements PcapPacketHandler<T> {
	private static Log log = LogFactory.getLog(JnetpcapPacketProcessor.class);

	int packetNumber = 0;
	private PacketReassembler packetReassembler;
	
	public JnetpcapPacketProcessor(PacketReassembler packetReassembler) {
		this.packetReassembler = packetReassembler;
	}

	public int getTotalNumberOfPackets() {
		return packetNumber;
	}

	@Override
	public void nextPacket(PcapPacket packet, T ignored) 
	{
		packetNumber++;
		if (log.isDebugEnabled()) {
			log.debug("processing #" + packetNumber + " " + packet);
		}
		
		Ip4 ip = new Ip4();
		Tcp tcp = new Tcp();
		if (packet.hasHeader(ip) && packet.hasHeader(tcp))
		{
			packetReassembler.reassemble(new JnetpcapTcpPacket(packet.getCaptureHeader(), ip, tcp));
		}
	}
}

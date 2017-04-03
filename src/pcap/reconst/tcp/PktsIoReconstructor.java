package pcap.reconst.tcp;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Map;

import io.pkts.PacketHandler;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import io.pkts.Pcap;
import io.pkts.protocol.Protocol;
import pcap.reconst.tcp.packet.PktsIoTcpPacket;

public class PktsIoReconstructor implements Reconstructor {
	private static Log log = LogFactory.getLog(JnetpcapReconstructor.class);

	private PacketReassembler packetReassembler;

	public PktsIoReconstructor(PacketReassembler packetReassembler) {
		this.packetReassembler = packetReassembler;
	}

	public Map<TcpConnection, TcpReassembler> reconstruct(String filename, StatusHandle status)
			throws Exception {
		if (log.isDebugEnabled()) {
			log.debug("reconstructing " + filename + " ...");
		}

		final Pcap pcap = Pcap.openStream(filename);

		pcap.loop(new PacketHandler() {
			@Override
			public boolean nextPacket(final Packet packet) throws IOException {
				if (packet.hasProtocol(Protocol.TCP)) {
					PktsIoTcpPacket pktsIoTcpPacket = new PktsIoTcpPacket((TCPPacket) packet.getPacket(Protocol.TCP));
					packetReassembler.reassemble(pktsIoTcpPacket);
				}

				return true;
			}
		});

		pcap.close();

		return packetReassembler.getReassembledPackets();
	}
}

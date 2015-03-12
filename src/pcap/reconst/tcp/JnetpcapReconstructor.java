/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.tcp;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jnetpcap.Pcap;


public class JnetpcapReconstructor implements Reconstructor {
	private static Log log = LogFactory.getLog(JnetpcapReconstructor.class);

	private PacketReassembler packetReassembler;

	public JnetpcapReconstructor(PacketReassembler packetReassembler) {
		this.packetReassembler = packetReassembler;
	}

	public Map<TcpConnection, TcpReassembler> reconstruct(String filename)
			throws Exception {
		if (log.isDebugEnabled()) {
			log.debug("reconstructing " + filename + " ...");
		}
		
		StringBuilder errorBuffer = new StringBuilder();
		Pcap pcap = Pcap.openOffline(filename, errorBuffer);
		JnetpcapPacketProcessor<Integer> packetProcessor = new JnetpcapPacketProcessor<Integer>(packetReassembler);
		pcap.loop(Pcap.LOOP_INFINITE, packetProcessor, 1);
		pcap.close();
		
		return packetReassembler.getReassembledPackets();
	}
}

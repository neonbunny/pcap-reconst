/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.tcp;

import java.util.Map;

import jpcap.JpcapCaptor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class JpcapReconstructor implements Reconstructor {
	private static Log log = LogFactory.getLog(JpcapReconstructor.class);

	private PacketReassembler packetReassembler;

	public JpcapReconstructor(PacketReassembler packetReassembler) {
		this.packetReassembler = packetReassembler;
	}

	public Map<TcpConnection, TcpReassembler> reconstruct(String filename, StatusHandle status)
			throws Exception {
		if (log.isDebugEnabled()) {
			log.debug("reconstructing " + filename + " ...");
		}
		final JpcapCaptor captor = JpcapCaptor.openFile(filename);
		captor.setFilter("tcp", true);
		JpcapPacketProcessor jpcapPacketProcessor = new JpcapPacketProcessor(
				packetReassembler);

		status.setCancellable(new StatusHandle.Cancellable() {
			public void cancel() {
				captor.breakLoop(); 
			}
		});
		captor.processPacket(-1, jpcapPacketProcessor);
		captor.close();
		return packetReassembler.getReassembledPackets();
	}

}

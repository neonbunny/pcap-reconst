package pcap.reconst.tcp;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapClosedException;

import pcap.reconst.ex.PcapException;


public class JnetpcapReconstructor implements Reconstructor {
	private static Log log = LogFactory.getLog(JnetpcapReconstructor.class);

	private PacketReassembler packetReassembler;

	public JnetpcapReconstructor(PacketReassembler packetReassembler) {
		this.packetReassembler = packetReassembler;
	}

	public Map<TcpConnection, TcpReassembler> reconstruct(String filename, StatusHandle status)
			throws Exception {
		if (log.isDebugEnabled()) {
			log.debug("reconstructing " + filename + " ...");
		}
		
		StringBuilder errorBuffer = new StringBuilder();
		final Pcap pcap = Pcap.openOffline(filename, errorBuffer);
		
		if (pcap == null)
		{
			throw new PcapException(errorBuffer.toString());
		}
		
		PcapBpfProgram program = new PcapBpfProgram();
		String expression = "tcp";
		pcap.compile(program, expression, 0, 0);
		pcap.setFilter(program);

		JnetpcapPacketProcessor<Integer> packetProcessor = new JnetpcapPacketProcessor<Integer>(packetReassembler);
		status.setCancellable(new StatusHandle.Cancellable() {
			public void cancel() {
				try
				{
					pcap.breakloop();
				}
				catch (PcapClosedException pce)
				{
					//Ignore, it may have completed on its own at this point.
				}
			}
		});
		pcap.loop(Pcap.LOOP_INFINITE, packetProcessor, 1);
		pcap.close();
		
		return packetReassembler.getReassembledPackets();
	}
}

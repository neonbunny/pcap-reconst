/*
 * Author: Chris Neasbitt
 */

package pcap.reconst.tcp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import pcap.reconst.tcp.packet.PlaceholderTcpPacket;
import pcap.reconst.tcp.packet.TcpPacket;

public class TcpReassembler {
	private static Log log = LogFactory.getLog(TcpReassembler.class);

	private TcpSequenceCounter reqCounter = null, respCounter = null;
	private List<TcpPacket> orderedPackets = new ArrayList<TcpPacket>();
	private List<Integer> reqIndexes = new ArrayList<Integer>();
	private List<Integer> respIndexes = new ArrayList<Integer>();
	private byte[] packetData = null;
	private Map<Integer, Integer> packetPositions = new HashMap<Integer, Integer>();

	private boolean rebuildData = true;

	public boolean isIncomplete() {
		for (TcpPacket packet : orderedPackets) {
			if (packet instanceof PlaceholderTcpPacket) {
				return true;
			}
		}
		return false;
	}

	public boolean isEmpty() {
		return orderedPackets.isEmpty();
	}
	
	private void checkBuildPacketData(){
		if (rebuildData || packetData == null) {
			buildPacketData();
			rebuildData = false;
		}
	}

	/**
	 * Gets the content of the stream as a String with the default platform encoding.
	 * 
	 * @return the content of the stream as a String with the default platform encoding.
	 */
	public String getOrderedPacketData() {
		return new String(getOrderedPacketDataBytes());
	}
	
	/**
	 * Gets the content of the stream as a byte[].
	 * 
	 * @return the content of the stream as a byte[].
	 */
	public byte[] getOrderedPacketDataBytes() {
		checkBuildPacketData();
		return packetData;
	}
	
	/**
	 * Gets a copy of a subsection of the stream content as a byte[].
	 * 
	 * @param start Offset into the overall stream from which to start adding to the result.
	 * @param end Offset in the overall stream to no longer include in the result.
	 * @return A subsection of the stream content as a byte[] or the whole stream if 
	 * the start or end values are outside of the valid range.
	 */
	public byte[] getOrderedPacketDataBytes(int start, int end) 
	{
		byte[] stream = getOrderedPacketDataBytes();
		if(start < 0 || end > stream.length)
		{
			return stream;
		}
		else 
		{
			return Arrays.copyOfRange(getOrderedPacketDataBytes(), start, end);
		}
	}
	
	public List<TcpPacket> getOrderedPackets(){
		return this.orderedPackets;
	}

	private void buildPacketData() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		for (int i = 0; i < orderedPackets.size(); i++) {
			byte[] data = orderedPackets.get(i).getData();
			
			if (data != null && data.length > 0) {
				int startpos = baos.size();
				try {
					baos.write(data);
					
					packetPositions.put(baos.size(), i);

					if (log.isDebugEnabled()) {
						log.debug("Start position: " + startpos + " End position: "
								+ baos.size() + "\n" + new String(data));
					}
				} catch (IOException e) {
					log.error("Unable to add packet data at stream offset : " + startpos, e);
				}
			}
		}
		packetData = baos.toByteArray();
	}
	
	//start and end are indexes in the reconstructed output
	//left is start index, right is end index
	private ImmutablePair<Integer, Integer> getStartandEndPacketIndexes
		(int start, int end){
		if(start > end){
			throw new RuntimeException("start: " + start + " must be <= end: " + end);
		}
		List<Integer> positions = new ArrayList<Integer>(
				packetPositions.keySet());
		Collections.sort(positions);
		int startPacket = -1, endPacket = -1;
		
		for (int pos : positions) {
			if (startPacket == -1 && start < pos) {
				startPacket = packetPositions.get(pos);
			}
			if (endPacket == -1 && end <= pos) {
				endPacket = packetPositions.get(pos);
			}
		}
		
		return ImmutablePair.of(startPacket, endPacket);
	}
	
	//start and end are indexes in the reconstructed output
	//returns true iff there are missing packets in between the packets that
	//contributed the start index and the end index in the reconstructed 
	//output
	public boolean errorBetween(int start, int end){
		ImmutablePair<Integer, Integer> indexes = 
				getStartandEndPacketIndexes(start, end);
		
		if(log.isDebugEnabled()){
			log.debug("Looking for error between start Packet: " + indexes.left + 
					" end Packet: " + indexes.right);
		}
		
		
		for(int i = indexes.left; i < indexes.right; i++){
			if(orderedPackets.get(i) instanceof PlaceholderTcpPacket){
				if(log.isDebugEnabled()){
					log.debug("Found placeholder packet at " + i + " Length: " + orderedPackets.get(i).getLength());
				}
				return true;
			}
		}
		
		return false;
	}
	
	public MessageMetadata getMessageMetadata(int beginIndex, int endIndex) {
		checkBuildPacketData();

		ImmutablePair<Integer, Integer> indexes = 
				getStartandEndPacketIndexes(beginIndex, endIndex);
		TcpPacket startPacket = orderedPackets.get(indexes.left),
				endPacket = orderedPackets.get(indexes.right);

		if (startPacket != null) {
			double startTS = startPacket.getTimestampSec() + (startPacket.getTimestampUSec()/1000000.0);		
			double endTS = endPacket.getTimestampSec() + (endPacket.getTimestampUSec()/1000000.0);
			TimestampPair ts = new TimestampPair(startTS, endTS);
			TcpConnection conn = new TcpConnection(startPacket);

			if (log.isDebugEnabled()) {
				log.debug(ts + "\n" + conn);
			}

			return new MessageMetadata(ts, conn);
		}

		return null;
	}

	public MessageMetadata getMessageMetadata(String needle) {
		checkBuildPacketData();

		int beginIndex = getOrderedPacketData().indexOf(needle);
		int endIndex = beginIndex + needle.length();

		return this.getMessageMetadata(beginIndex, endIndex);
	}
	
	public TcpConnection getTcpConnection(int beginIndex, int endIndex) {
		MessageMetadata mdata = this.getMessageMetadata(beginIndex, endIndex);
		if (mdata != null) {
			return mdata.getTcpConnection();
		}
		return null;
	}
	
	public TcpConnection getTcpConnection(String needle) {
		MessageMetadata mdata = this.getMessageMetadata(needle);
		if (mdata != null) {
			return mdata.getTcpConnection();
		}
		return null;
	}
	
	public TimestampPair getTimestampRange(int beginIndex, int endIndex) {
		MessageMetadata mdata = this.getMessageMetadata(beginIndex, endIndex);
		if (mdata != null) {
			return mdata.getTimestamps();
		}
		return null;
	}

	public TimestampPair getTimestampRange(String needle) {
		MessageMetadata mdata = this.getMessageMetadata(needle);
		if (mdata != null) {
			return mdata.getTimestamps();
		}
		return null;
	}

	public TcpReassembler() {
	}

	/*
	 * The main function of the class receives a tcp packet and reconstructs the
	 * stream
	 */
	public void reassemblePacket(TcpPacket tcpPacket) throws Exception {
		if (log.isDebugEnabled()) {
			log.debug(String
					.format("captured_len = %d, len = %d, headerlen = %d, datalen = %d",
							tcpPacket.getCaptureLength(),
							tcpPacket.getLength(), tcpPacket.getHeaderLength(),
							tcpPacket.getDataLength()));
		}
		reassembleTcp(new TcpConnection(tcpPacket), tcpPacket);
	}

	private void reassembleTcp(TcpConnection tcpConnection, TcpPacket packet)
			throws Exception {
		if (log.isDebugEnabled()) {
			log.debug(String
					.format("sequence=%d ack_num=%d length=%d dataLength=%d synFlag=%s %s srcPort=%s %s dstPort=%s",
							packet.getSequence(), packet.getAckNum(),
							packet.getLength(), packet.getDataLength(),
							packet.getSyn(), tcpConnection.getSrcIp(),
							tcpConnection.getSrcPort(),
							tcpConnection.getDstIp(),
							tcpConnection.getDstPort()));
		}

		boolean first = false;
		PacketType packetType = null;

		// Now check if the packet is for this connection.
		InetAddress srcIp = tcpConnection.getSrcIp();
		int srcPort = tcpConnection.getSrcPort();

		// Check to see if we have seen this source IP and port before.
		// check both source IP and port; the connection might be between two
		// different ports on the same machine...
		if (reqCounter == null) {
			reqCounter = new TcpSequenceCounter(srcIp, srcPort);
			packetType = PacketType.Request;
			first = true;
		} else {
			if (reqCounter.getAddress().equals(srcIp)
					&& reqCounter.getPort() == srcPort) {
				// check if request is already being handled... this is a
				// fragmented packet
				packetType = PacketType.Request;
			} else {
				if (respCounter == null) {
					respCounter = new TcpSequenceCounter(srcIp, srcPort);
					packetType = PacketType.Response;
					first = true;
				} else if (respCounter.getAddress().equals(srcIp)
						&& respCounter.getPort() == srcPort) {
					// check if response is already being handled... this is a
					// fragmented packet
					packetType = PacketType.Response;
				}
			}
		}

		if (packetType == null) {
			throw new Exception(
					"ERROR in TcpReassembler: Too many or too few addresses!");
		}

		if (log.isDebugEnabled()) {
			log.debug((isRequest(packetType) ? "request" : "response")
					+ " packet...");
		}

		TcpSequenceCounter currentCounter = isRequest(packetType) ? reqCounter
				: respCounter;
		updateSequence(first, currentCounter, packet, packetType);
	}

	private boolean isRequest(PacketType packetType) {
		return PacketType.Request == packetType;
	}

	private void updateSequence(boolean first, TcpSequenceCounter tcpSeq,
			TcpPacket packet, PacketType type) throws IOException {
		// figure out sequence number stuff
		if (first) {
			// this is the first time we have seen this src's sequence number
			tcpSeq.setSeq(packet.getSequence() + packet.getDataLength());
			if (packet.getSyn()) {
				tcpSeq.incrementSeq();
			}
			// add to ordered packets
			addOrderedPacket(packet, type);
			return;
		}

		// if we are here, we have already seen this src, let's try and figure
		// out if this packet is in the right place
		if (packet.getSequence() < tcpSeq.getSeq()) {
			if (!this.checkPlaceholders(packet, type)) {
				if (log.isDebugEnabled()) {
					log.debug("Unable to place packet.\n" + packet);
				}
			}
		}

		if (packet.getSequence() == tcpSeq.getSeq()) {
			// packet in sequence
			tcpSeq.addToSeq(packet.getDataLength());
			if (packet.getSyn()) {
				tcpSeq.incrementSeq();
			}
			addOrderedPacket(packet, type);
		} else {
			// out of order packet
			if (packet.getDataLength() > 0
					&& packet.getSequence() > tcpSeq.getSeq()) {
				PlaceholderTcpPacket ppacket = new PlaceholderTcpPacket(
						packet.getSourceIP(), packet.getSourcePort(),
						packet.getDestinationIP(), packet.getDestinationPort(),
						tcpSeq.getSeq(),
						(int) (packet.getSequence() - this
								.getLastOrderedSequence(type)));
				this.addOrderedPacket(ppacket, type);
				this.addOrderedPacket(packet, type);
				tcpSeq.setSeq(packet.getSequence());
			}
		}
	}

	private boolean checkPlaceholders(TcpPacket packet, PacketType type) {
		boolean retval = false;
		for (Integer index : this.getPacketIndexes(type)) {
			TcpPacket pospacket = orderedPackets.get(index);
			if (pospacket instanceof PlaceholderTcpPacket) {
				// overlap placeholder beginning
				if (packet.getSequence() < pospacket.getSequence()
						&& (packet.getSequence() + packet.getLength()) < (pospacket
								.getSequence() + pospacket.getLength())) {
					if (log.isDebugEnabled()) {
						log.debug("Overlap placeholder beginning.\n" + packet);
					}
					// retval = true;
					// break;
				}

				// overlap placeholder ending
				if (packet.getSequence() > pospacket.getSequence()
						&& (packet.getSequence() + packet.getLength()) > (pospacket
								.getSequence() + pospacket.getLength())) {
					if (log.isDebugEnabled()) {
						log.debug("Overlap placeholder ending.\n" + packet);
					}
					// retval = true;
					// break;
				}

				// in the middle of the place holder
				if (packet.getSequence() >= pospacket.getSequence()
						&& (packet.getSequence() + packet.getLength()) <= (pospacket
								.getSequence() + pospacket.getLength())) {

					// exactly fits a place holder
					if (packet.getSequence() == pospacket.getSequence()
							&& packet.getLength() == pospacket.getLength()) {
						this.setOrderedPacket(packet, type, index);
					} else {
						long leftlen = packet.getSequence()
								- pospacket.getSequence();
						long leftseq = pospacket.getSequence();
						long rightlen = pospacket.getSequence()
								+ pospacket.getLength() - packet.getSequence()
								+ packet.getLength();
						long rightseq = packet.getSequence()
								+ packet.getLength();

						PlaceholderTcpPacket lpacket = new PlaceholderTcpPacket(
								packet.getSourceIP(), packet.getSourcePort(),
								packet.getDestinationIP(),
								packet.getDestinationPort(), leftseq,
								(int) leftlen);
						PlaceholderTcpPacket rpacket = new PlaceholderTcpPacket(
								packet.getSourceIP(), packet.getSourcePort(),
								packet.getDestinationIP(),
								packet.getDestinationPort(), rightlen,
								(int) rightseq);

						if (lpacket.getLength() > 0) {
							this.setOrderedPacket(lpacket, type, index);
							this.insertOrderedPacket(packet, type, index + 1);
							if (rpacket.getLength() > 0) {
								this.insertOrderedPacket(rpacket, type,
										index + 2);
							}
						} else {
							this.setOrderedPacket(packet, type, index);
							this.insertOrderedPacket(rpacket, type, index + 1);
						}
					}
					retval = true;
					break;
				}
			}
		}
		return retval;
	}

	private List<Integer> getPacketIndexes(PacketType type) {
		return isRequest(type) ? reqIndexes : respIndexes;
	}

	private void incPacketIndexes(int greaterthan, int inc) {
		for (int i = 0; i < reqIndexes.size(); i++) {
			if (reqIndexes.get(i) > greaterthan) {
				reqIndexes.set(i, reqIndexes.get(i) + inc);
			}
		}
		for (int i = 0; i < respIndexes.size(); i++) {
			if (respIndexes.get(i) > greaterthan) {
				respIndexes.set(i, respIndexes.get(i) + inc);
			}
		}
	}

	private void setOrderedPacket(TcpPacket packet, PacketType type, int index) {
		rebuildData = true;
		Integer indexObj = index;
		orderedPackets.set(index, packet);
		if (isRequest(type)) {
			if (!reqIndexes.contains(indexObj)) {
				reqIndexes.add(indexObj);
			}
			if (respIndexes.contains(indexObj)) {
				respIndexes.remove(indexObj);
			}
		} else {
			if (!respIndexes.contains(indexObj)) {
				respIndexes.add(indexObj);
			}
			if (reqIndexes.contains(indexObj)) {
				reqIndexes.remove(indexObj);
			}
		}
	}

	private void insertOrderedPacket(TcpPacket packet, PacketType type,
			int index) {
		rebuildData = true;
		orderedPackets.add(index, packet);
		incPacketIndexes(index, 1);
		if (isRequest(type)) {
			reqIndexes.add(index);
		} else {
			respIndexes.add(index);
		}
	}

	private void addOrderedPacket(TcpPacket packet, PacketType type) {
		rebuildData = true;
		orderedPackets.add(packet);
		if (isRequest(type)) {
			reqIndexes.add(orderedPackets.size() - 1);
		} else {
			respIndexes.add(orderedPackets.size() - 1);
		}
	}

	private long getLastOrderedSequence(PacketType type) {
		TcpPacket last = null;
		if (isRequest(type)) {
			if (reqIndexes.size() > 0) {
				last = orderedPackets
						.get(reqIndexes.get(reqIndexes.size() - 1));
			}
		} else {
			if (respIndexes.size() > 0) {
				last = orderedPackets
						.get(respIndexes.get(respIndexes.size() - 1));
			}
		}
		if (last != null) {
			return last.getSequence();
		}

		return -1;
	}
}

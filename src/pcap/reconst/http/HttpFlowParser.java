package pcap.reconst.http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpException;

import pcap.reconst.http.datamodel.RecordedHttpFlow;
import pcap.reconst.http.datamodel.RecordedHttpRequestMessage;
import pcap.reconst.http.datamodel.RecordedHttpResponse;
import pcap.reconst.tcp.MessageMetadata;
import pcap.reconst.tcp.TcpConnection;
import pcap.reconst.tcp.TcpReassembler;

public class HttpFlowParser {

	private static Log log = LogFactory.getLog(HttpFlowParser.class);

	public static final Pattern HTTP_REQ_REGEX = Pattern.compile("(GET|POST|HEAD|OPTIONS|PUT|DELETE|TRACE|CONNECT)\\s\\S+\\sHTTP/[1-2]\\.[0-9]\\s");
	//Don't treat HTTP 100 status codes as the start of a response, e.g. "100 Continue" is a provisional response 
	//and will later result in another response code for the same conversation
	public static final Pattern HTTP_RESP_REGEX = Pattern.compile("HTTP/[1-2]\\.[0-9]\\s[2-5][0-9][0-9](.[0-9][0-9]?)?\\s");

	private final static int ZERO = 0;

	private Map<TcpConnection, TcpReassembler> map;

	public HttpFlowParser(Map<TcpConnection, TcpReassembler> map) {
		this.map = map;
	}
	
	protected static SortedMap<Integer, Boolean> buildMessageStartIndex(String buf){
		List<Integer> reqIndexes = matchStartLocations(buf, HTTP_REQ_REGEX);
		List<Integer> respIndexes = matchStartLocations(buf, HTTP_RESP_REGEX);
		SortedMap<Integer, Boolean> matchLocations = new TreeMap<Integer, Boolean>();
		for(Integer key : reqIndexes){
			matchLocations.put(key, true); //true = request
		}
		for(Integer key : respIndexes){
			matchLocations.put(key, false); //false = response
		}
		return matchLocations;
	}
	
	//TODO fix for the chunked encoding case containing a request in a chunk
	private static boolean isPipelined(TcpReassembler assembler){
		SortedMap<Integer, Boolean> matchLocations = buildMessageStartIndex(assembler.getOrderedPacketData());
		List<Integer> matchIndexes = new ArrayList<Integer>(matchLocations.keySet());
		
		if(matchIndexes.size() > 1){
			for(int i = 0; i < matchIndexes.size() - 1; i++){
				int posA = matchIndexes.get(i);
				int posB = matchIndexes.get(i+1);
				int posC = assembler.getOrderedPacketData().length();
				//i+2 should give us the end of packet at i+1
				if(i+2 < matchIndexes.size()){
					posC = matchIndexes.get(i+2);
				}
				boolean messageA = matchLocations.get(posA);
				boolean messageB = matchLocations.get(posB);
				boolean errorBetween = assembler.errorBetween(posA, posC);
								
				//if there are errors in the stream then two requests can
				//look pipelined for the fact that a response is missing
				if(messageA && messageB && !errorBetween){
					return true;
				}
			}
		}
		return false;
	}

	
	private static List<FlowBuf> parsePipelinedFlows(String buf, TcpReassembler assembler){
		List<FlowBuf> retval = new ArrayList<FlowBuf>();
		SortedMap<Integer, Boolean> matchLocations = buildMessageStartIndex(buf);
		List<Integer> matchIndexes = new ArrayList<Integer>(matchLocations.keySet());
		
		if(log.isDebugEnabled()){
			String logval = "Match Locations:\n";
			for(int index : matchIndexes){
				logval += index + " " + (matchLocations.get(index) ? "Request" : "Response") + "\n";
			}
			log.debug(logval);
		}
		
		if(matchIndexes.size() > 0){
			//get rid of any leading responses
			while(!matchLocations.get(matchIndexes.get(ZERO))){
				matchIndexes.remove(ZERO);
				if(matchIndexes.isEmpty()){
					break;
				}
			}
		
			List<FlowBuf> pReqSection = new ArrayList<FlowBuf>();
			List<FlowBuf> pRespSection = new ArrayList<FlowBuf>();
			FlowBuf singReqFlow = null;
			for(int i = 0; i < matchIndexes.size(); i++){
				boolean current = matchLocations.get(matchIndexes.get(i));
				if(i + 1 < matchIndexes.size()){
					boolean next = matchLocations.get(matchIndexes.get(i + 1));
					if(current){
						FlowBuf reqchunk = new FlowBuf();
						reqchunk.reqStart = matchIndexes.get(i);
						reqchunk.reqEnd = matchIndexes.get(i+1);
						if(next){
							//if request then request
							pReqSection.add(reqchunk);
						} else {
							//if request then response
							if(pReqSection.size() > 0){
								pReqSection.add(reqchunk);
							} else {
								singReqFlow=reqchunk;
							}
						}
					} else {
						FlowBuf respchunk = new FlowBuf();
						respchunk.respStart = matchIndexes.get(i);
						respchunk.respEnd = matchIndexes.get(i+1);
						if(next){
							//if response then request
							if(singReqFlow != null){								
								retval.add(mergeFlowBuf(singReqFlow, respchunk));
								singReqFlow = null;
							} else {
								pRespSection.add(respchunk);
							}
							if(pReqSection.size() != pRespSection.size()){
								if(log.isDebugEnabled()){
									log.debug("Unequal pipeline sections. Returning parsed stream section.");
								}
								return retval;
								/*if(log.isWarnEnabled()){
									log.warn("Unequal pipeline sections. Attempting to fix.");
								}
								if(fixPipelinedSections(pReqSection, pRespSection, assembler)){
									if(log.isInfoEnabled()){
										log.info("Fixed unequal pipeline sections.");
									}
								} else {
									throw new RuntimeException("Unable to fix unequal pipeline sections.");
								}*/
							}
						} else {
							//if response then response
							if(pReqSection.size() > 0){
								pRespSection.add(respchunk);
							} else {
								//throw new RuntimeException("Two adjacent responses in error.");
								if(log.isDebugEnabled()){
									log.debug("Two adjacent responses in error. Returning parsed stream section.");
								}
								return retval;
							}
						}
						if(pReqSection.size() == pRespSection.size()){
							for(int q = 0; q < pReqSection.size(); q++){
								retval.add(mergeFlowBuf(pReqSection.get(q), pRespSection.get(q)));
							}
							pReqSection.clear();
							pRespSection.clear();
						}
					}
				} else {
					//i = len - 1
					if(current){ // if request
						FlowBuf reqchunk = new FlowBuf();
						reqchunk.reqStart = matchIndexes.get(i);
						reqchunk.reqEnd = buf.length();
						pReqSection.add(reqchunk);
						for(FlowBuf req : pReqSection){
							retval.add(req);
						}
					} else { //if response
						FlowBuf respchunk = new FlowBuf();
						respchunk.respStart = matchIndexes.get(i);
						respchunk.respEnd = buf.length();
						if(singReqFlow != null){ //single flow							
							retval.add(mergeFlowBuf(singReqFlow, respchunk));
							singReqFlow = null;
						} else if (pReqSection.size() > 0) { //pipelined request section
							pRespSection.add(respchunk);
						} else {
							//throw new RuntimeException("Single unmatched response");
							if(log.isDebugEnabled()){
								log.debug("Single unmatched response. Returning parsed stream section.");
							}
							return retval;
						}
					}
					
					//if at the end of the stream, should be the end of the pipelined section
					if(pReqSection.size() == pRespSection.size()){
						//if pReqSection and pRespSection are empty then the loop is never executed
						for(int q = 0; q < pReqSection.size(); q++){							
							retval.add(mergeFlowBuf(pReqSection.get(q), pRespSection.get(q)));
						}
						pReqSection.clear();
						pRespSection.clear();
					} else {
						if(pReqSection.size() > pRespSection.size()){
							//throw new RuntimeException("Incompleted pipelined response section.");
							if(log.isDebugEnabled()){
								log.debug("Incomplete pipelined response section. Returning parsed stream section.");
							}
						} else {
							//throw new RuntimeException("Incompleted pipelined request section.");
							if(log.isDebugEnabled()){
								log.debug("Incomplete pipelined request section. Returning parsed stream section.");
							}
						}
					}
				}
			}
		}
		return retval;
	}
	
	
	private static List<Integer> matchStartLocations(String buf, Pattern httpReqRegex){
		List<Integer> indexes = new ArrayList<Integer>();
		Matcher matcher = httpReqRegex.matcher(buf);
		while (matcher.find()) {
			indexes.add(matcher.start());
		}
		return indexes;
	}

	private static List<FlowBuf> splitFlows(String buf) {
		List<FlowBuf> retval = new ArrayList<FlowBuf>();
		SortedMap<Integer, Boolean> matchLocations = buildMessageStartIndex(buf);
		List<Integer> matchIndexes = new ArrayList<Integer>(matchLocations.keySet());
		
		if(matchIndexes.size() > 0){
			
			//get rid of any leading responses
			while(!matchLocations.get(matchIndexes.get(ZERO))){
				matchIndexes.remove(ZERO);
				if(matchIndexes.isEmpty()){
					break;
				}
			}
			
			if(log.isDebugEnabled()){
				log.debug("Number of match indexes: " + matchIndexes.size());
			}
			
			FlowBuf temp = null;
			for(int i = 0; i < matchIndexes.size(); i++){
				boolean current = matchLocations.get(matchIndexes.get(i));
				if(i + 1 < matchIndexes.size()){
					boolean next = matchLocations.get(matchIndexes.get(i + 1));
					if(current){ //is request
						if(!next){ //is response
							if(temp == null){
								temp = new FlowBuf();
								temp.reqStart = matchIndexes.get(i);
								temp.reqEnd = matchIndexes.get(i + 1);
							} else {
								throw new RuntimeException("FlowBuf should be null at this point.");
								// FlowBuf should be null, error
							}
						} else { //is request
							if(log.isDebugEnabled()){
								log.debug("Two adjacent requests in non pipelined flow.  " +
										"Request starting at index " + matchIndexes.get(i) + " has no response.");
							}
							temp = new FlowBuf();
							temp.reqStart = matchIndexes.get(i);
							temp.reqEnd = matchIndexes.get(i + 1);
							retval.add(temp);
							temp = null;
							// two requests back to back, error
						}
					} else { //is response
						if(next){ //is request
							if(temp != null){
								temp.respStart = matchIndexes.get(i);
								temp.respEnd = matchIndexes.get(i+1);
								retval.add(temp);
								temp = null;
							} else {
								throw new RuntimeException("FlowBuf should not be null at this point.");
								// FlowBuf should not be null, error
							}
						} else { // is response
							if(log.isDebugEnabled()){
								log.debug("Two adjacent responses in non pipelined flow.  " +
										"Response starting at index " + matchIndexes.get(i+1) + " has no request.");
							}
							temp.respStart = matchIndexes.get(i);
							temp.respEnd = matchIndexes.get(i+1);
							retval.add(temp);
							temp = null;
							i++; //skips the erroneous response
							// two responses back to back, error
						}
					}
				} else {
					if(current){ // is request
						if(temp == null){
							temp = new FlowBuf();
							temp.reqStart = matchIndexes.get(i);
							temp.reqEnd = buf.length();
							retval.add(temp);
						} else {
							throw new RuntimeException("FlowBuf should be null at this point.");
							// FlowBuf should be equal to null, error
						}
					} else { // is response
						if(temp != null){
							temp.respStart = matchIndexes.get(i);
							temp.respEnd = buf.length();
							retval.add(temp);
						} else {
							throw new RuntimeException("FlowBuf should not be null at this point.");
							// FlowBuf should not be equal to null, error
						}
					}
				}
			}
		}
		
		return retval;
	}
	

	@SuppressWarnings("unused")
	private int numRequests(String buf) {
		int retval = this.numMatches(buf, HTTP_REQ_REGEX);
		if (log.isDebugEnabled()) {
			log.debug("Number of Requests: " + retval);
		}
		return retval;
	}

	@SuppressWarnings("unused")
	private int numResponses(String buf) {
		int retval = this.numMatches(buf, HTTP_RESP_REGEX);
		if (log.isDebugEnabled()) {
			log.debug("Number of Responses: " + retval);
		}
		return retval;
	}


	private int numMatches(String buf, Pattern regex) {
		int retval = 0;
		Matcher matcher = regex.matcher(buf);
		while (matcher.find()) {
			retval++;
		}
		return retval;
	}

	private static boolean hasRequestData(String buf) {
		return hasDesiredData(buf, HTTP_REQ_REGEX);
	}

	private static boolean hasDesiredData(String buf, Pattern regex) {
		Matcher matcher = regex.matcher(buf);
		return matcher.find();
	}
	
	private List<RecordedHttpFlow> parseFlows(TcpConnection connection, TcpReassembler assembler) {
		String flowbuf = assembler.getOrderedPacketData();
		List<RecordedHttpFlow> outputlist = new ArrayList<RecordedHttpFlow>();
		if (hasRequestData(flowbuf)) {

			List<FlowBuf> flows = null;
			if(isPipelined(assembler)){
				if(log.isDebugEnabled()){
					log.debug("Parsing pipelined stream. " + connection);
				}
				flows = parsePipelinedFlows(flowbuf, assembler);
				
			} else {
				if(log.isDebugEnabled()){
					log.debug("Parsing non-pipelined stream. " + connection);
				}
				flows = splitFlows(flowbuf);
			}
			for (FlowBuf flow : flows) {
				try {
					RecordedHttpFlow httpOutput = this.toHttp(flow, assembler);
					outputlist.add(httpOutput);
				} catch (Exception e) {
					if (log.isErrorEnabled()) {
						log.error("", e);
					}
				}
			}
		}
		return outputlist;
	}
	

	public Map<TcpConnection, List<RecordedHttpFlow>> parse() {
		Map<TcpConnection, List<RecordedHttpFlow>> httpPackets = 
				new HashMap<TcpConnection, List<RecordedHttpFlow>>();

		for (Entry<TcpConnection, TcpReassembler> entry : map.entrySet() ) {
			try{
				List<RecordedHttpFlow> flows = parseFlows(entry.getKey(), entry.getValue());
				if(flows.size() > 0){
					httpPackets.put(entry.getKey(), flows);
				} else {
					if(log.isDebugEnabled()){
						log.debug("No HTTP flows found in stream: " + entry.getKey());
					}
				}
				if (log.isDebugEnabled()) {
					log.debug("Processed stream: " + entry.getKey());
				}
			} catch (Exception e) {
				if(log.isErrorEnabled()){
					log.error("Error processing stream: " + entry.getKey(), e);
				}
			}
		}
		return httpPackets;
	}
	
	protected RecordedHttpFlow toHttp(FlowBuf flow, TcpReassembler assembler) throws IOException, HttpException {
		if (log.isDebugEnabled()) {
			log.debug("Processing flow " + flow);
		}
		byte[] rawdata = null;
		if (flow.hasRequestData()) {
			rawdata = assembler.getOrderedPacketDataBytes(flow.reqStart, flow.reqEnd);
			
			RecordedHttpRequestMessage request;
			RecordedHttpResponse response = null;

			if (flow.hadResponseData()) {
				byte[] respBytes = assembler.getOrderedPacketDataBytes(flow.respStart, flow.respEnd);
				byte[] reqRespbytes = new byte[rawdata.length + respBytes.length];
				System.arraycopy(rawdata, 0, reqRespbytes, 0, rawdata.length);
				System.arraycopy(respBytes, 0, reqRespbytes, rawdata.length, respBytes.length);
				rawdata = reqRespbytes;
				request = getRequest(flow, assembler);
				response = getResponse(flow, assembler);
			} else {
				request = getRequest(flow, assembler);
			}
			return new RecordedHttpFlow(rawdata, request, response);
		}
		return null;
	}
	
	
	protected static RecordedHttpRequestMessage getRequest(FlowBuf flow, TcpReassembler assembler) throws IOException, HttpException{
		String reqstring = assembler.getOrderedPacketData().substring(
				flow.reqStart, flow.reqEnd);
		MessageMetadata mdata = assembler
				.getMessageMetadata(flow.reqStart, flow.reqEnd);
		return (RecordedHttpRequestMessage)RecordedHttpMessageParser.
				parseRecordedRequest(reqstring, mdata);
	}
	
	
	protected static RecordedHttpResponse getResponse(FlowBuf flow, 
			TcpReassembler assembler) throws IOException, HttpException{
		String respstring = assembler.getOrderedPacketData().substring(
				flow.respStart, flow.respEnd);
		MessageMetadata mdata = assembler
				.getMessageMetadata(flow.respStart, flow.respEnd);
		return (RecordedHttpResponse)RecordedHttpMessageParser.
				parseRecordedResponse(respstring, mdata);
	}

	
	public static FlowBuf mergeFlowBuf(FlowBuf reqChunk, FlowBuf respChunk){
		FlowBuf retval = new FlowBuf();
		retval.reqStart = reqChunk.reqStart;
		retval.reqEnd = reqChunk.reqEnd;
		retval.respStart = respChunk.respStart;
		retval.respEnd = respChunk.respEnd;
		return retval;
	}
	
	protected static class FlowBuf{
		public int reqStart = -1, reqEnd = -1, respStart = -1, respEnd = -1;
		
		public boolean hasRequestData(){
			return reqStart != -1 && reqEnd != -1;
		}
		
		public boolean hadResponseData(){
			return respStart != -1 && respEnd != -1;
		}
		
		@Override
		public String toString(){
			return "Request Start: " + reqStart + " Request End: " + reqEnd + " Response Start: " + 
					respStart + " Response End: " + respEnd;
		}
	}

}

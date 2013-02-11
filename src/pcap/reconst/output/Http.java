/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.output;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import pcap.reconst.beans.Headers;
import pcap.reconst.beans.InputData;
import pcap.reconst.beans.TcpConnection;
import pcap.reconst.beans.TimestampPair;
import pcap.reconst.reconstructor.TcpReassembler;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Http {
	private static Log log = LogFactory.getLog(Http.class);
    
    public static final String HTTP_REQ_REGEX = "(GET|POST|HEAD|OPTIONS|PUT|DELETE|TRACE|CONNECT)\\s\\S+\\sHTTP/[1-2]\\.[0-9]\\s";
    public static final String HTTP_RESP_REGEX = "HTTP/[1-2]\\.[0-9]\\s[1-5][0-9][0-9](.[0-9][0-9]?)?\\s";
    

    public final static int ZERO = 0;

    private Map<TcpConnection, TcpReassembler> map;

    public Http(Map<TcpConnection, TcpReassembler> map) {
        this.map = map;
    }
    
    public List<String> splitFlows(String buf){
    	List<String> retval = new ArrayList<String>();
    	List<Integer> indexes = new ArrayList<Integer>();
    	Pattern pat = Pattern.compile(HTTP_REQ_REGEX);
    	Matcher matcher = pat.matcher(buf);
    	while(matcher.find()){
    		indexes.add(matcher.start());
    	}
    	for(int i = 0; i < indexes.size(); i++){
    		if(i == indexes.size() - 1){
    			retval.add(buf.substring(indexes.get(i)));
    		} else {
    			retval.add(buf.substring(indexes.get(i), indexes.get(i+1)));
    		}
    	}
    	return retval;
    }
    
    public int numRequests(String buf){
    	int retval = this.numMatches(buf, HTTP_REQ_REGEX);
    	if(log.isDebugEnabled()){
    		log.debug("Number of Requests: " + retval);
    	}
    	return retval;
    }
    
    public int numResponses(String buf){
    	return this.numMatches(buf, HTTP_RESP_REGEX);
    }
    
    public int responseStart(String buf){
    	Pattern pat = Pattern.compile(HTTP_RESP_REGEX);
    	Matcher matcher = pat.matcher(buf);
    	if(matcher.find()){
    		return matcher.start();
    	}
    	return -1;
    }
    
    private int numMatches(String buf, String regex){
       	int retval = 0;
    	Pattern pat = Pattern.compile(regex);
    	Matcher matcher = pat.matcher(buf);
    	while(matcher.find()){
    		retval++;
    	}
    	return retval;
    }
    
    public boolean hasRequestData(String buf){
    	return this.hasDesiredData(buf, HTTP_REQ_REGEX); 
    }
    
    public boolean hasResponseData(String buf){
    	return this.hasDesiredData(buf, HTTP_RESP_REGEX); 
    }
    
    private boolean hasDesiredData(String buf, String regex){
       	Pattern pat = Pattern.compile(regex);
    	Matcher matcher = pat.matcher(buf);
    	return matcher.find();
    }
    
    public List<HttpOutput> packetizeFlow(TcpReassembler assembler){
    	String flowbuf = assembler.getOrderedPacketData();
    	List<HttpOutput> outputlist = new ArrayList<HttpOutput>();
        if (this.hasRequestData(flowbuf)) {
        	
        	List<String> flows;
        	if(this.numRequests(flowbuf) > 1){
        		flows = this.splitFlows(flowbuf);
        	} else {
        		flows = new ArrayList<String>();
        		flows.add(flowbuf);
        	}
        	
        	for(String flow : flows){
                try {
                    HttpOutput httpOutput = toHttp(flow, assembler);
                    outputlist.add(httpOutput);
                } catch (Exception e) {
                	if(log.isErrorEnabled()){
                		log.error("", e);
                	}
                }
        	}
        }
        return outputlist;
    }
    
    
    public Map<TcpConnection, List<HttpOutput>> packetize() {
        Map<TcpConnection, List<HttpOutput>> httpPackets = 
        		new HashMap<TcpConnection, List<HttpOutput>>();
        
        
        for (TcpConnection connection : map.keySet()) {
            httpPackets.put(connection, this.packetizeFlow(map.get(connection)));
            if(log.isDebugEnabled()){
            	log.debug("Processed stream: " + connection);
            }
        }
        return httpPackets;
    }

    public HttpOutput toHttp(String flow, TcpReassembler assembler){
    	if(log.isDebugEnabled()){
    		log.debug("total length " + flow.length());
    	}
        if (this.hasRequestData(flow)) {
            InputData request;
            InputData response = null;

            if (this.hasResponseData(flow)) {
            	int responseIndex = this.responseStart(flow);
            	request = getRequest(flow, responseIndex, assembler);
                int responseLength = flow.length() - responseIndex;
                response = getResponse(flow, responseLength, responseIndex, assembler);
            } else {
                request = getRequest(flow, flow.length(), assembler);
            }
            return new HttpOutput(flow.getBytes(), request, response);
        }
        return null;
    }

    private InputData getResponse(String data, int responseLength, 
    		int responseIndex, TcpReassembler assembler) {
        byte[] response = new byte[responseLength];
        System.arraycopy(data.getBytes(), responseIndex, response, ZERO, responseLength);
        String responseAsString = new String(response);
        Headers responseHeaders = getHeaders(responseAsString);
        TimestampPair tsPair = assembler.getTimestampRange(responseAsString);
        if(log.isDebugEnabled()){
	        log.debug(responseHeaders);
	        int responseContentLength = responseHeaders.getContentLength();
	        log.debug(responseContentLength);
        }
        return new InputData(response, responseHeaders, tsPair);
    }

    private InputData getRequest(String data, int responseIndex, TcpReassembler assembler) {
        byte[] request = new byte[responseIndex];
        System.arraycopy(data.getBytes(), ZERO, request, ZERO, responseIndex);
        String requestAsString = new String(request);
        Headers requestHeaders = getHeaders(requestAsString);
        TimestampPair tsPair = assembler.getTimestampRange(requestAsString);
        if(log.isDebugEnabled()){
	        log.debug(requestHeaders);
	        int requestContentLength = requestHeaders.getContentLength();
	        log.debug(requestContentLength);
        }
        return new InputData(request, requestHeaders, tsPair);
    }

    private static Headers getHeaders(String stringWithHeaders) {
        Headers headers = new Headers();
        String[] tokens = stringWithHeaders.split("\r\n");
        for (String token : tokens) {
            if (StringUtils.isEmpty(token)) {
                break;
            }
            if (token.contains(": ")) {
        		String[] values = token.split(": ");
        		if(values.length > 1){
        			headers.addHeader(values[0], values[1]);
        		} else {
        			headers.addHeader(values[0], null);
        		}
            }
        }
        return headers;
    }
}
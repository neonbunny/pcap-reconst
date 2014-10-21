package pcap.reconst.http.datamodel;

import java.net.InetAddress;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.ProtocolVersion;
import org.apache.http.RequestLine;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;

import pcap.reconst.tcp.MessageMetadata;

public class RecordedHttpEntityEnclosingRequest extends
		BasicHttpEntityEnclosingRequest implements RecordedHttpRequestMessage {

	protected MessageMetadata messdata;
	
	private static Log log = LogFactory.getLog(RecordedHttpEntityEnclosingRequest.class);
	
	public RecordedHttpEntityEnclosingRequest(RequestLine requestline, 
			MessageMetadata messdata) {
		super(requestline);
		this.messdata = messdata;
	}

	public RecordedHttpEntityEnclosingRequest(String method, String uri, 
			MessageMetadata messdata) {
		super(method, uri);
		this.messdata = messdata;
	}

	public RecordedHttpEntityEnclosingRequest(String method, String uri,
			ProtocolVersion ver, MessageMetadata messdata) {
		super(method, uri, ver);
		this.messdata = messdata;
	}
	
	public String getUrl(){
		String host = this.getFirstHeader("Host").getValue();
		String retval = "http://";
		if (host != null) {
			retval += host;
		} else {
			retval += messdata.getDstIp().toString().replace("/", "");
		}
		return retval + this.getRequestLine().getUri();
	}


	public double getStartTS() {
		return this.messdata.getTimestamps().getStartTS();
	}

	public double getEndTS() {
		return this.messdata.getTimestamps().getEndTS();
	}

	public InetAddress getSrcIp() {
		return this.messdata.getSrcIp();
	}

	public InetAddress getDstIp() {
		return this.messdata.getDstIp();
	}

	public int getSrcPort() {
		return this.messdata.getSrcPort();
	}

	public int getDstPort() {
		return this.messdata.getDstPort();
	}
	
	public boolean equals(Object obj){
		boolean retval = false;
		if(obj instanceof RecordedHttpEntityEnclosingRequest){
			RecordedHttpEntityEnclosingRequest mess = (RecordedHttpEntityEnclosingRequest)obj;
			try{
				retval = mess.getDstIp().equals(this.getDstIp()) &&
					mess.getDstPort() == this.getDstPort() &&
					mess.getSrcIp().equals(this.getSrcIp()) &&
					mess.getSrcPort() == this.getSrcPort() &&
					mess.getStartTS() == this.getStartTS() &&
					mess.getEndTS() == this.getEndTS() &&
					Utils.equals(mess.getAllHeaders(), this.getAllHeaders()) &&
					Utils.equals(mess.getRequestLine(), this.getRequestLine()) &&
					mess.getEntity().getContent() == this.getEntity().getContent();
			}  catch (Exception e){
				if(log.isDebugEnabled()){
					log.debug("Error retrieving content.", e);
				}
			}
		}
		return retval;
	}

}

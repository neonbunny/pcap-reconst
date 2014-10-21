package pcap.reconst.http.datamodel;

import java.net.InetAddress;

import org.apache.http.ProtocolVersion;
import org.apache.http.RequestLine;
import org.apache.http.message.BasicHttpRequest;

import pcap.reconst.tcp.MessageMetadata;

public class RecordedHttpRequest extends BasicHttpRequest implements
		RecordedHttpRequestMessage {

	protected MessageMetadata messdata;
	
	public RecordedHttpRequest(RequestLine requestline,
			MessageMetadata messdata) {
		super(requestline);
		this.messdata = messdata;
	}

	public RecordedHttpRequest(String method, String uri, 
			MessageMetadata messdata) {
		super(method, uri);
		this.messdata = messdata;
	}

	public RecordedHttpRequest(String method, String uri, 
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
		if(obj instanceof RecordedHttpRequest){
			RecordedHttpRequest mess = (RecordedHttpRequest)obj;
			return mess.getDstIp().equals(this.getDstIp()) &&
					mess.getDstPort() == this.getDstPort() &&
					mess.getSrcIp().equals(this.getSrcIp()) &&
					mess.getSrcPort() == this.getSrcPort() &&
					mess.getStartTS() == this.getStartTS() &&
					mess.getEndTS() == this.getEndTS() &&
					Utils.equals(mess.getAllHeaders(), this.getAllHeaders()) &&
					Utils.equals(mess.getRequestLine(), this.getRequestLine());		
		}
		return false;
	}

}

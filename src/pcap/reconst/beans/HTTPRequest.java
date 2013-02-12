package pcap.reconst.beans;

import java.net.InetAddress;

public class HTTPRequest extends HTTPMessage {
	
	public HTTPRequest(byte[] data, TimestampPair ts, InetAddress src,
			int srcport, InetAddress dst, int dstport) {
		super(data, ts, src, srcport, dst, dstport);
	}
	
	public HTTPRequest(byte[] data, MessageMetadata mdata){
		super(data, mdata);
	}
	
	public HTTPRequest(byte[] data, TimestampPair ts, TcpConnection conn){
		super(data, ts, conn);
	}
	
	public String getUrl(){
		String host = this.headers.getValue("Host");
		String retval = "http://";
		if(host != null){
			retval += host;
			if(this.conn.getDstPort() != 80){
				retval = retval + ":" + conn.getDstPort();
			}
		} else {
			retval += this.conn.getDstIp().toString().replace("/", "");
			if(this.conn.getDstPort() != 80){
				retval = retval + ":" + conn.getDstPort();
			}
		}
		return retval + this.getPath();
	}

	public String getPath(){
		String[] parts = new String(this.data).split("\r\n", 2)[0]
				.split("\\s");
		return parts[1];
	}
	
	public String getMethod(){
		String[] parts = new String(this.data).split("\r\n", 2)[0]
				.split("\\s");
		return parts[0];
	}
}
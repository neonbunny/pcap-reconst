package pcap.reconst.http.datamodel;

import java.util.Arrays;
import java.util.Comparator;

import org.apache.http.Header;
import org.apache.http.RequestLine;
import org.apache.http.StatusLine;

public class Utils {
	
	public static boolean equals(RequestLine a, RequestLine b){
		return a.getProtocolVersion().equals(b.getProtocolVersion()) &&
				a.getMethod().equals(b.getMethod()) &&
				a.getUri().equals(b.getUri());
	}	
		
	public static boolean equals(StatusLine a, StatusLine b){
		return a.getProtocolVersion().equals(b.getProtocolVersion()) &&
				a.getStatusCode() == b.getStatusCode() &&
				a.getReasonPhrase().equals(b.getReasonPhrase());
	}
	
	public static boolean equals(Header[] a, Header[] b){
		if(a.length == b.length){
			Header[] acopy = sort(a);
			Header[] bcopy = sort(b);
			for(int i = 0; i < acopy.length; i++){
				Header ahead = acopy[i];
				Header bhead = bcopy[i];
				if(!ahead.getName().equals(bhead.getName()) || 
						!ahead.getValue().equals(bhead.getValue())){
					return false;
				}
			}
			return true;
		}
		return false;
	}
	
	private static Header[] sort(Header[] a){
		Header[] copy = Arrays.copyOf(a, a.length);
		Arrays.sort(copy, new Comparator<Header>(){
			public int compare(Header o1, Header o2) {
				int val = o1.getName().compareTo(o2.getName());
				if(val == 0){
					val = o1.getValue().compareTo(o2.getValue());
				}
				return val;
			}
		});
		return copy;
	}

}

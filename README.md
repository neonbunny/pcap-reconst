__pcap-reconst__ implements tcp resequencing and http flow extraction.
This project is a fork of the original [pcap-reconst](http://code.google.com/p/pcap-reconst/) 
project with numerous corrections and improvements.

Download
--------

Source is hosted on github: 

[github.com/neonbunny/pcap-reconst](http://github.com/neonbunny/pcap-reconst)

Requirements
------------

* [Java](http://www.oracle.com/technetwork/java/javase/downloads/index.html) 6 or greater
* [commons-lang](http://commons.apache.org/lang/) 3.1
* [commons-logging](http://commons.apache.org/logging/) 1.1.1
* [HttpComponents-HttpCore](http://hc.apache.org/httpcomponents-core-ga/index.html) 4.2.1
* [jpcap](https://github.com/mgodave/Jpcap) or [jnetpcap](http://jnetpcap.com/) 1.4.r1425

__jpcap__ and __jnetpcap__ are both wrappers for libpcap or winpcap.


Usage
-----

See the HttpReconstructorExample class in the pcap.reconst.example package for usage.

Todo
----
* Test with chunked transfer encoding.

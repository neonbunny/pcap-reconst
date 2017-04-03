package pcap.reconst.tcp.packet;

import org.apache.commons.lang3.builder.ToStringBuilder;

public abstract class AbstractTcpPacket implements TcpPacket {
    @Override
    public String toString()
    {
        ToStringBuilder tsb = new ToStringBuilder(this)
                .append("Seconds", getTimestampSec())
                .append("uSeconds", getTimestampUSec())
                .append("Source IP", getSourceIP())
                .append("Source Port", getSourcePort())
                .append("Destination IP", getDestinationIP())
                .append("Destination Port", getDestinationPort())
                .append("Sequence Number", getSequence())
                .append("Acknowledgement Number", getAckNum())
                .append("Length", getLength())
                .append("Cap Length", getCaptureLength())
                .append("Data Length", getDataLength())
                .append("Header Length", getHeaderLength());


        if (getSyn())
        {
            tsb.append("SYN");
        }

        if (getAck())
        {
            tsb.append("ACK");
        }

        if (getFin())
        {
            tsb.append("FIN");
        }

        if (getPsh())
        {
            tsb.append("PSH");
        }

        return tsb.build();
    }
}

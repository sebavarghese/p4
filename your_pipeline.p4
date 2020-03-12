/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes 
#include "include/headers.p4"
#include "include/parsers.p4"

const bit<16> L2_LEARN_ETHER_TYPE = 0x1234;

#define MAX_TIMESTAMP 10
#define MAX_FLOW 10
const bit<32> MAX_NUM_RTTS = 1024;

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
//Register to keep track of number of RTTS
    register <bit<32>>(MAX_NUM_RTTS) current_rtt_index;
//Registers to store synTimestamp and ackTimestamp
    register <bit<48>> (MAX_TIMESTAMP) tcpSynRegister;
    register <bit<48>> (MAX_TIMESTAMP) tcpAckRegister;
/*    register <bit<32>> (MAX_TIMESTAMP) tcpSynHashRegister;
    register <bit<32>> (MAX_TIMESTAMP) tcpAckHashRegister;*/
//Register to store RTT
    register <bit<48>> (MAX_TIMESTAMP) tcpRTTRegister;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    /*************************************************************************
    ******************************  D M A C   ********************************
    *************************************************************************/

    action tunnel_ingress(bit<16> tunnel_id, bit<16> pw_id) {
        hdr.tunnel.setValid();
        hdr.tunnel.tunnel_id = tunnel_id;
        hdr.tunnel.pw_id = pw_id;
        hdr.tunnel.proto_id = hdr.ethernet.etherType;
        hdr.ethernet.etherType = TYPE_TUNNEL;
    }

    action broadcast() {
        //Empty action that was not necessary, we just call it when there is a table miss
    }

    action forward(egressSpec_t egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table dmac {
        key = {
            hdr.ethernet.dstAddr: exact;
            standard_metadata.ingress_port: exact;
        }
        actions = {
            tunnel_ingress;
            forward;
            broadcast;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = broadcast;
    }

    /*************************************************************************
    ****************************  T U N N E L   ******************************
    *************************************************************************/

    action tunnel_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action tunnel_egress(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.etherType = hdr.tunnel.proto_id;
        hdr.tunnel.setInvalid();
    }

    table tunnel_exact {
        key = {
            hdr.tunnel.tunnel_id: exact;
            hdr.tunnel.pw_id: exact;
        }
        actions = {
            tunnel_forward;
            tunnel_egress;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    /*************************************************************************
    *************************  M U L T I C A S T   ***************************
    *************************************************************************/

    action set_mcast_grp(bit<16> mcast_grp) {
        standard_metadata.mcast_grp = mcast_grp;
    }

    table select_mcast_grp {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_mcast_grp;
            NoAction;
        }
        size = 32;
        default_action =  NoAction;
    }

    /*************************************************************************
    ********************************  E C M P   ******************************
    *************************************************************************/

    // action set_nhop(macAddr_t dstAddr, egressSpec_t port) {
    //     hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    //     hdr.ethernet.dstAddr = dstAddr;
    //     standard_metadata.egress_spec = port;
    //     hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    // }

    action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){
        hash(meta.ecmp_hash,
	    HashAlgorithm.crc16,
	    (bit<1>)0,
	    {hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol},
	    num_nhops);

	    meta.ecmp_group_id = ecmp_group_id;
    }

    table ecmp_group_to_nhop {
	    key = {
            meta.ecmp_group_id: exact;
            meta.ecmp_hash: exact;
        }
        actions = {
            drop;
            forward;
        }
        size = 1024;
    }

    table ipv4_lpm {
        key = {
            hdr.ethernet.dstAddr: exact;
            standard_metadata.ingress_port: exact;
        }
        actions = {
            ecmp_group;
            forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }


    /*************************************************************************
     ********************************  RTT  **********************************
     *************************************************************************/
    action computeSynHash(bit<16> num_nhops) {
	    hash(meta.syn_hash,
			    HashAlgorithm.crc16,
			    (bit<1>)0,
			    {hdr.ipv4.srcAddr,
			    hdr.ipv4.dstAddr,
			    hdr.tcp.srcPort,
			    hdr.tcp.dstPort,
			    hdr.ipv4.protocol},
			    num_nhops);
    }
    action computeAckHash(bit<16> num_nhops){
	    hash(meta.ack_hash,
			    HashAlgorithm.crc16,
			    (bit<1>)0,
			    {hdr.ipv4.srcAddr,
			    hdr.ipv4.dstAddr,
			    hdr.tcp.srcPort,
			    hdr.tcp.dstPort,
			    hdr.ipv4.protocol},
			    num_nhops);
    }
    action get_syn_packetTime(bit<1> x) {
	    tcpSynRegister.write(meta.syn_hash, standard_metadata.ingress_global_timestamp);
    }
    action get_ack_packetTime(bit<1> y) {
	    tcpAckRegister.write(meta.ack_hash, standard_metadata.ingress_global_timestamp);
    }
    table tcp_syn_match {
	    key = {
		    hdr.tcp.syn: exact;
		    standard_metadata.ingress_port: exact;
	    }
	    actions = {
		    computeSynHash;
		    get_syn_packetTime;
		    NoAction;
	    }
	    size = 1;
	    default_action = NoAction();
    }
    table tcp_ack_match {
	    key = {
		    hdr.tcp.ack: exact;
		    standard_metadata.ingress_port: exact;
	    }
	    actions = {
		    computeAckHash;
		    get_ack_packetTime;
		    NoAction;
            }
            size = 1;
            default_action = NoAction();
    }


    /*************************************************************************
    *****************************  A P P L Y   *******************************
    *************************************************************************/

    apply {
        
        if (!hdr.tunnel.isValid()) {
            //Process only non-tunneled packets.
            if (dmac.apply().hit) {
                //
            } else {
                select_mcast_grp.apply();
            }
        } 
        
        if (hdr.tunnel.isValid()) {
            // Process all tunneled packets.
            
            switch (tunnel_exact.apply().action_run) {

                tunnel_egress: {
                    //
                }

                tunnel_forward: {
                    if (hdr.ipv4.isValid() && hdr.tcp.isValid()){
                        switch (ipv4_lpm.apply().action_run){
                            ecmp_group: {
                                ecmp_group_to_nhop.apply();
                            }
                        }
                    }
                }
            }
        }
        if (hdr.tcp.isValid()) {
            if(hdr.tcp.syn == 1 && hdr.tcp.ack == 0) {
                tcp_syn_match.apply();
            }
            if(hdr.tcp.ack == 1 && hdr.tcp.syn == 0) {
                tcp_ack_match.apply();
            }
            bit<32> rtt_index;
            bit<48> interval;
            bit<48> synPacketTime;
            bit<48> ackPacketTime;
	    tcpSynRegister.read(synPacketTime, meta.syn_hash);
	    tcpAckRegister.read(ackPacketTime, meta.ack_hash);
	    if( ackPacketTime != 0 && synPacketTime != 0) {
		    current_rtt_index.read(rtt_index, 0);
		    interval = ackPacketTime - synPacketTime;
		    tcpRTTRegister.write(rtt_index, interval);
		    tcpRTTRegister.read(interval, rtt_index);
		    current_rtt_index.write(0, (rtt_index + 1) % MAX_NUM_RTTS);
	    }
	}
    }
}


    /*************************************************************************
     ****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    action drop_2(){
        mark_to_drop(standard_metadata);
    }

    apply {
        if (standard_metadata.egress_port == standard_metadata.ingress_port)
            drop_2();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

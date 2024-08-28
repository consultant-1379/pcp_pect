/*
 * packetLossStandAlone.hpp
 *
 *  Created on: 10Feb14
 *      Author: efitleo
 */

#ifndef PACKETLOSSSTANDALONE_HPP_
#define PACKETLOSSSTANDALONE_HPP_


// following for testing packet loss stand alone
void initCounters(pktLossInfo *tcp_flow);
void handleNewFlow(const struct tcphdr *tcp, uint32_t  tcpPayloadSize, int pkt_loss_direction, pktLossInfo *tcp_flow, const unsigned long long *currPktTime);
void handleTCPPacketHeadingToInternet(const struct tcphdr *tcp, uint32_t tcpPayloadSize, pktLossInfo *tcp_flow, const unsigned long long *currPktTime);
void handleTCPPacketHeadingToUE(const struct tcphdr *tcp, uint32_t tcpPayloadSize, pktLossInfo *tcp_flow, const unsigned long long *currPktTime);
void resetPerROPCounters(pktLossInfo *tcp_flow);
int testPacketLoss(int argc, char **argv);
void cleanupPacketLossStandAlone();
unsigned int pktLossCheckDataIntegrity(pktLossInfo *tcp_flow, int direction);

#endif /* PACKETLOSSSTANDALONE_HPP_ */

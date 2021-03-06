// $Id: SendOpStackM.nc,v 1.1 2005/10/13 17:12:13 chien-liang Exp $

/* Agilla - A middleware for wireless sensor networks.
 * Copyright (C) 2004, Washington University in Saint Louis 
 * By Chien-Liang Fok.
 * 
 * Washington University states that Agilla is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the current version of the GNU Lesser General Public License 
 * as published by the Free Software Foundation.
 * 
 * Agilla is distributed in the hope that it will be useful, but 
 * THERE ARE NO WARRANTIES, WHETHER ORAL OR WRITTEN, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO, IMPLIED WARRANTIES OF 
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR USE.
 *
 * YOU UNDERSTAND THAT AGILLA IS PROVIDED "AS IS" FOR WHICH NO 
 * WARRANTIES AS TO CAPABILITIES OR ACCURACY ARE MADE. THERE ARE NO 
 * WARRANTIES AND NO REPRESENTATION THAT AGILLA IS FREE OF 
 * INFRINGEMENT OF THIRD PARTY PATENT, COPYRIGHT, OR OTHER 
 * PROPRIETARY RIGHTS.	THERE ARE NO WARRANTIES THAT SOFTWARE IS 
 * FREE FROM "BUGS", "VIRUSES", "TROJAN HORSES", "TRAP DOORS", "WORMS", 
 * OR OTHER HARMFUL CODE.	
 *
 * YOU ASSUME THE ENTIRE RISK AS TO THE PERFORMANCE OF SOFTWARE AND/OR 
 * ASSOCIATED MATERIALS, AND TO THE PERFORMANCE AND VALIDITY OF 
 * INFORMATION GENERATED USING SOFTWARE. By using Agilla you agree to 
 * indemnify, defend, and hold harmless WU, its employees, officers and 
 * agents from any and all claims, costs, or liabilities, including 
 * attorneys fees and court costs at both the trial and appellate levels 
 * for any loss, damage, or injury caused by your actions or actions of 
 * your officers, servants, agents or third parties acting on behalf or 
 * under authorization from you, as a result of using Agilla. 
 *
 * See the GNU Lesser General Public License for more details, which can 
 * be found here: http://www.gnu.org/copyleft/lesser.html
 */


/**
 * Sends an agent's opstack.
 *
 * @author Chien-Liang Fok
 */
#include "Timer.h"

module SendOpStackM {
	provides {
	interface StdControl;
	interface Init;
	interface PartialAgentSenderI as SendOpStack;
	}
	uses {
	interface MessageBufferI;
	interface OpStackI;	
	interface AMSend as Send_OpStack;
	interface AMSend as SerialSend_OpStack;
	interface ErrorMgrI as Error;
	interface Packet;
	}
}
implementation {
	uint8_t _numRetransmits;	
	
	AgillaAgentContext* _context;
	AgillaAgentID _id;	
	uint16_t _dest;	// the one-hop address
	
	uint8_t _startAddr, _nxtStartAddr, _msgNum;
	
	task void doSend();
	
	command error_t Init.init() {
	return SUCCESS;
	}

	command error_t StdControl.start() {
	return SUCCESS;
	}

	command error_t StdControl.stop() {
	return SUCCESS;
	}	
	
	inline void sendFail() {	
	if (++_numRetransmits < AGILLA_SNDR_MAX_RETRANSMITS) {
		if (!post doSend() != SUCCESS)
		signal SendOpStack.sendDone(_context, FAIL);				
	} else 
		signal SendOpStack.sendDone(_context, FAIL);					
	}
	
	command error_t SendOpStack.send(AgillaAgentContext* context, AgillaAgentID id,
	uint8_t op, uint16_t dest) 
	{		
	if (post doSend() == SUCCESS) {
		_numRetransmits = _startAddr = _nxtStartAddr = _msgNum = 0;

		_context = context;
		_id = id;
		_dest = dest;
		return SUCCESS;
	} else
		return FAIL;
	}
	
	task void doSend() {
	//message_t* msg = call MessageBufferI.getBuffer();
	message_t* msg = call MessageBufferI.getMsg();
	//struct AgillaOpStackMsg *osMsg = (struct AgillaOpStackMsg *)msg->data;
	AgillaOpStackMsg *osMsg = (AgillaOpStackMsg *)(call Packet.getPayload(msg, sizeof(AgillaOpStackMsg)));
	osMsg->id = _id;
	osMsg->startAddr = _startAddr;		
	_nxtStartAddr = call OpStackI.fillMsg(_context, _startAddr, osMsg);	 
	if (_dest == AM_UART_ADDR){
		if (call SerialSend_OpStack.send(_dest, msg, sizeof(AgillaOpStackMsg)) != SUCCESS)
		sendFail();
	} else{
		if (call Send_OpStack.send(_dest, msg, sizeof(AgillaOpStackMsg)) != SUCCESS)
		sendFail();
	}
	}

	event void Send_OpStack.sendDone(message_t* m, error_t success)	{
	if (success != SUCCESS /*|| !m->ack*/)
		sendFail();
	else {
		_startAddr = _nxtStartAddr;			
		if (++_msgNum * AGILLA_OS_MSG_SIZE < _context->opStack.sp) {
		if (post doSend() != SUCCESS)
			signal SendOpStack.sendDone(_context, FAIL);				
		} else
		signal SendOpStack.sendDone(_context, SUCCESS);				
	}
	 // return SUCCESS;
	}
	
	event void SerialSend_OpStack.sendDone(message_t* m, error_t success)	{
	if (success != SUCCESS /*|| !m->ack*/)
		sendFail();
	else {
		_startAddr = _nxtStartAddr;			
		if (++_msgNum * AGILLA_OS_MSG_SIZE < _context->opStack.sp) {
		if (post doSend() != SUCCESS)
			signal SendOpStack.sendDone(_context, FAIL);				
		} else
		signal SendOpStack.sendDone(_context, SUCCESS);				
	}
	 // return SUCCESS;
	}
	
	/**
	 * This is executed whenever an ACK message times out.
	 */
	/*event result_t Ack_Timer.fired() {	
	_numRetransmits++;	
	
	#if DEBUG_AGENT_SENDER
		dbg(DBG_USR1, "SendOpStackM: Ack_Timer.fired(): TIMED OUT! (# = %i)\n", _numRetransmits);
	#endif	 
	
	if (_numRetransmits < AGILLA_SNDR_MAX_TIMEOUTS) {
		post doSend();
	} else {
		#if DEBUG_AGENT_SENDER
		dbg(DBG_USR1, "SendOpStackM: Ack_Timer.fired(): Max numTimeouts reached.\n");
		#endif	
		signalDone(FAIL);
	}
	return SUCCESS;
	}*/
	
	/**
	 * This is signalled when an ACK message is received.
	 */
	/*event TOS_MsgPtr Rcv_Ack.receive(TOS_MsgPtr m) {
	if (_state == WAITING) {
		AgillaAckOpStackMsg* aMsg = (AgillaAckOpStackMsg*)m->data;
		if (aMsg->id.id == _id.id && aMsg->startAddr == _startAddr) {		
		call Ack_Timer.stop();
		if (aMsg->accept) {
			_startAddr = _nxtStartAddr;			
			if (++_msgNum * AGILLA_OS_MSG_SIZE < _context->opStack.sp)
			post doSend();
			else
			signalDone(SUCCESS);
		} else {
			#if DEBUG_AGENT_SENDER
			dbg(DBG_USR1, "SendOpStackM: Rcv_Ack.receive: The opStack message %i was rejected.\n", msgNum);
			#endif			
			signalDone(FAIL);
		}
		} else {
		#if DEBUG_AGENT_SENDER
		dbg(DBG_USR1, "SendOpStackM: Rcv_Ack.receive: The ACK was not for this agent.\n");
		#endif	
		}
	} else {
		#if DEBUG_AGENT_SENDER
		dbg(DBG_USR1, "SendOpStackM: Rcv_Ack.receive: Received an ACK while not WAITING.\n");
		#endif
	}
	return m;
	}*/	

}

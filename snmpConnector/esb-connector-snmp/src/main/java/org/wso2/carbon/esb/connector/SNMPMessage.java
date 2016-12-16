/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.esb.connector;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.soap.SOAPBody;
import org.apache.commons.lang.StringUtils;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseException;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.wso2.carbon.connector.core.AbstractConnector;
import org.wso2.carbon.connector.core.ConnectException;
import org.wso2.carbon.connector.core.Connector;

import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

public class SNMPMessage extends AbstractConnector implements Connector {
    private static Snmp snmp;

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {
        String ipAddress = (String) messageContext.getProperty(SNMPConstants.IP_ADDRESS);
        String port = (String) messageContext.getProperty(SNMPConstants.PORT);
        String oids = (String) messageContext.getProperty(SNMPConstants.OIDs);
        String snmpVersion = (String) messageContext.getProperty(SNMPConstants.SNMP_VERSION);
        String community = (String) messageContext.getProperty(SNMPConstants.COMMUNITY);
        String retries = (String) messageContext.getProperty(SNMPConstants.RETRIES);
        String timeout = (String) messageContext.getProperty(SNMPConstants.TIMEOUT);
        String requestId = (String) messageContext.getProperty(SNMPConstants.REQUEST_ID);
        try {
            // Create TransportMapping and Listen
            snmp = (Snmp) messageContext.getProperty(SNMPConstants.SNMP);
            // Create the PDU object
            PDU pdu = new PDU();
            createPDU(oids, pdu);
            pdu.setType(PDU.GET);
            pdu.setRequestID(new Integer32(Integer.parseInt(requestId)));
            //sending data to Agent
            if (log.isDebugEnabled()) {
                log.debug("Sending Request to Agent.");
            }
            ResponseEvent response = snmp.get(pdu, getTarget(community, ipAddress, port, snmpVersion,
                    retries, timeout));
            // Process Agent Response
            if (response != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Got Response from Agent.");
                }
                PDU responsePDU = response.getResponse();
                if (responsePDU != null) {
                    int errorStatus = responsePDU.getErrorStatus();
                    int errorIndex = responsePDU.getErrorIndex();
                    String errorStatusText = responsePDU.getErrorStatusText();
                    if (errorStatus == PDU.noError) {
                        OMElement element;
                        if (log.isDebugEnabled()) {
                            log.debug("Snmp Get Response.");
                        }
                        String responseMessage = responsePDU.getVariableBindings().toString();
                        String result = SNMPConstants.START_TAG + responseMessage + SNMPConstants.END_TAG;
                        element = transformMessages(result);
                        preparePayload(messageContext, element);
                    } else {
                        throw new SynapseException("Request Failed:" + "Status = " + errorStatus +
                                " Index=" + errorIndex + " Status Text=" + errorStatusText);
                    }
                } else {
                    throw new SynapseException("Error: Response PDU is null.");
                }
            } else {
                log.error("Error: Agent Timeout.");
            }
            stop();
        } catch (Exception e) {
            handleException("IO error occur " + e.getMessage(), e, messageContext);
        }
    }

    /**
     * This method is capable of handling multiple OIDs
     *
     * @param oids set of OIDs
     * @return pdu
     * @throws IOException
     */
    public PDU createPDU(String oids, PDU pdu) throws IOException {
        List<String> oidsList = null;
        if (StringUtils.isNotEmpty(oids)) {
            oidsList = Arrays.asList(oids.split(SNMPConstants.OID_SPLITER));
        }
        if (oidsList != null) {
            for (String oid : oidsList) {
                pdu.add(new VariableBinding(new OID(oid)));
            }
        }
        return pdu;
    }

    /**
     * Since snmp4j relies on asynch req/resp we need a listener for responses which should be closed.
     */
    public void stop() throws IOException {
        snmp.close();
    }

    /**
     * Create Target Address object
     *
     * @return target
     */
    private static CommunityTarget getTarget(String community, String ipAddress, String port,
                                             String version, String retries, String timeout) {
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString(community));
        target.setAddress(new UdpAddress(ipAddress + SNMPConstants.COMBINER + port));
        target.setVersion(Integer.parseInt(version));
        target.setRetries(Integer.parseInt(retries));
        target.setTimeout(Integer.parseInt(timeout));
        return target;
    }

    /**
     * Prepare pay load
     *
     * @param messageContext The message context that is processed by a handler in the handle method
     * @param element        OMElement
     */
    private void preparePayload(MessageContext messageContext, OMElement element) {
        SOAPBody soapBody = messageContext.getEnvelope().getBody();
        for (Iterator itr = soapBody.getChildElements(); itr.hasNext(); ) {
            OMElement child = (OMElement) itr.next();
            child.detach();
        }
        for (Iterator itr = element.getChildElements(); itr.hasNext(); ) {
            OMElement child = (OMElement) itr.next();
            soapBody.addChild(child);
        }
    }

    /**
     * Create a OMElement
     *
     * @param output output
     * @return return resultElement
     * @throws XMLStreamException
     */
    private OMElement transformMessages(String output) throws XMLStreamException {
        OMElement resultElement;
        resultElement = AXIOMUtil.stringToOM(output);
        return resultElement;
    }
}

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
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.mp.SnmpConstants;
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
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class SendMessage extends AbstractConnector implements Connector {
    private static Snmp snmp;

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {
        String targetIpAddress = (String) messageContext.getProperty(SNMPConstants.TARGET_IP_ADDRESS);
        String targetPort = (String) messageContext.getProperty(SNMPConstants.TARGET_PORT);
        String oidValue = (String) messageContext.getProperty(SNMPConstants.OID_VALUE);
        String snmpVersion = (String) messageContext.getProperty(SNMPConstants.SNMP_VERSION);
        String community = (String) messageContext.getProperty(SNMPConstants.COMMUNITY);
        String retries = (String) messageContext.getProperty(SNMPConstants.RETRIES);
        String timeout = (String) messageContext.getProperty(SNMPConstants.TIMEOUT);
        try {
            //Create Transport Mapping
            snmp = (Snmp) messageContext.getProperty(SNMPConstants.SNMP);
            //Create PDU
            PDU pdu = new PDU();
            // To specify the system up time
            pdu.add(new VariableBinding(SnmpConstants.sysUpTime, new OctetString(new Date().toString())));
            // variable binding for Enterprise Specific objects, Severity (should be defined in MIB file)
            addPDU(oidValue, pdu);
            pdu.setType(PDU.NOTIFICATION);
            //Send the PDU
            snmp.send(pdu, getTarget(community, targetIpAddress, targetPort, snmpVersion, retries, timeout));
            OMElement element;
            String responseMessage = "Sending V2 Trap to " + targetIpAddress + " on Port " + targetPort;
            String result = SNMPConstants.START_TAG + responseMessage + SNMPConstants.END_TAG;
            element = transformMessages(result);
            preparePayload(messageContext, element);
            stop();//TODO :  use finally to  destroy or connection pool
        } catch (XMLStreamException e) {
            handleException("Error occur when constructing OMElement" + e.getMessage(), e, messageContext);
        } catch (IOException e) {
            handleException("Error in Sending V2 Trap to " + targetIpAddress + " on Port " +
                    targetPort + e.getMessage(), e, messageContext);
        }
    }
    //TODO: check performance test for existing one with Jmeter and use connection pool

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
    private static Target getTarget(String community, String ipAddress, String port, String version,
                                    String retries, String timeout) {
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString(community));
        target.setAddress(new UdpAddress(ipAddress + SNMPConstants.COMBINER + port));
        target.setVersion(Integer.parseInt(version));
        target.setRetries(Integer.parseInt(retries));
        target.setTimeout(Integer.parseInt(timeout));
        //TODO: Check timeout and retries
        return target;
    }

    /**
     * This method is capable of handling multiple OIDs
     *
     * @param oidValues set of OIDs and message pairs
     * @return pdu
     * @throws IOException
     */
    public PDU addPDU(String oidValues, PDU pdu) throws IOException {
        List<String> oidValuesList = null;
        if (StringUtils.isNotEmpty(oidValues)) {
            oidValuesList = Arrays.asList(oidValues.split(SNMPConstants.OID_SPLITER));
        }
        //TODO: make oidValue as json object
        if (oidValuesList != null) {
            for (String oid : oidValuesList) {
                String[] oidValue = oid.split(SNMPConstants.OID_VALUE_SPLITER);
                pdu.add(new VariableBinding(new OID(oidValue[Integer.parseInt(SNMPConstants.OID_INDEX)]),
                        new OctetString(oidValue[Integer.parseInt(SNMPConstants.MESSAGE_INDEX)])));
            }
        }
        return pdu;
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


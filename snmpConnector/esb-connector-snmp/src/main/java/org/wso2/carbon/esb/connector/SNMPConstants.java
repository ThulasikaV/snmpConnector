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

public class SNMPConstants {
    public static final String IP_ADDRESS = "ipAddress";
    public static final String PORT = "port";
    public static final String OIDs = "oids";
    public static final String SNMP_VERSION = "snmpVersion";
    public static final String COMMUNITY = "community";
    public static final String RETRIES = "retries";
    public static final String TIMEOUT = "timeout";
    public static final String REQUEST_ID = "requestId";
    public static final String TARGET_IP_ADDRESS = "targetIpAddress";
    public static final String TARGET_PORT = "targetPort";
    public static final String VERSION = "snmpTrapVersion";
    public static final String OID_VALUE = "oidValue";
    public static final String START_TAG = "<result><messageId>";
    public static final String END_TAG = "</messageId></result>";
    public static final String OID_INDEX = "0";
    public static final String MESSAGE_INDEX = "1";
    public static final String OID_VALUE_SPLITER = ":";
    public static final String OID_SPLITER = ",";
    public static final String COMBINER = "/";
    public static final String SNMP = "snmp";
}
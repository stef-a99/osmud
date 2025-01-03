/* Copyright 2018 osMUD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <mosquitto.h>

#include <errno.h>

#include "comms.h"
#include "oms_messages.h"
#include "oms_utils.h"
#include "dhcp_event.h"
#include "mud_manager.h"
#include "mudparser.h"

extern char *dnsWhiteListFile;
extern int noFailOnMudValidation;

int dhcpNewEventCount = 0;
int dhcpOldEventCount = 0;
int dhcpDeleteEventCount = 0;
int dhcpErrorEventCount = 0;
char message_buffer[256];
pthread_mutex_t message_mutex = PTHREAD_MUTEX_INITIALIZER;
char *topic;
char *mudurl_extension = "1.3.6.1.5.5.7.1.25";
char *mudsigner_extension = "1.3.6.1.5.5.7.1.30";


void resetDhcpCounters()
{
	dhcpNewEventCount = 0;
	dhcpOldEventCount = 0;
	dhcpDeleteEventCount = 0;
	dhcpErrorEventCount = 0;
}

void buildDhcpEventsLogMsg(char *buf, int bufSize)
{
	snprintf(buf, bufSize, "OSMUD:DHCP Stats: New: %d | Old: %d | Delete: %d | Errors: %d",
			dhcpNewEventCount, dhcpOldEventCount, dhcpDeleteEventCount, dhcpErrorEventCount);
	buf[bufSize-1] = '\0';
}

int buildPortRange(char *portBuf, int portBufSize, AceEntry *ace)
{
	int retval = 0; /* Return > 0 if there is an error with port assignments */

	snprintf(portBuf, portBufSize, "%s:%s", ace->lowerPort, ace->upperPort);
	portBuf[portBufSize-1] = '\0';

	return retval;
}

#define PORT_BUF_SIZE 512

int processFromAccess(char *aclName, char *aclType, AclEntry *acl, DhcpEvent *event) {
	int retval = 0;
	int actionResult = 0;
	int i, j;
	DomainResolutions *dnsInfo;
	char portRangeBuffer[PORT_BUF_SIZE];

	if (!acl) {
		logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_DEVICE_INTERFACE, "ERROR: NULL in *from* acl rule.");
		return 1;  /* It's an error situation */
	}

	for (i = 0; i < acl->aceCount; i++) {
		if (acl->aceList[i].aceType == ACLDNS) {
    		logOmsGeneralMessage(OMS_INFO, OMS_SUBSYS_DEVICE_INTERFACE, "Applying *from* dns ace rule.");

    		dnsInfo = resolveDnsEntryToIp(acl->aceList[i].dnsName);

    		// Need to check a return code to make sure the rule got applied correctly
    		installDnsRule(dnsInfo->domainName, event->ipAddress, event->macAddress, event->hostName, dnsWhiteListFile);

    		// Need to install a firewall rule for each IP that resolves
    		for (j = 0; j < dnsInfo->ipCount; j++) {
    			buildPortRange(portRangeBuffer, PORT_BUF_SIZE, &(acl->aceList[i]));
    			actionResult = installFirewallIPRule(event->ipAddress,
    													dnsInfo->ipList[j],
														portRangeBuffer,
														LAN_DEVICE_NAME,
														WAN_DEVICE_NAME,
														acl->aceList[i].protocol,
														acl->aceList[i].ruleName,
														acl->aceList[i].actionsForwarding,
														aclType, event->hostName);
				if (actionResult) {
					logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_DEVICE_INTERFACE, "Firewall rule installation failed");
					actionResult = 0;
					retval = 1; /* Set flag to indicate at least one firewall rule installation failed */
				}
    		}

    		freeDnsInfo(dnsInfo);
		} else {
    		logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DEVICE_INTERFACE, "Ignoring unimplemented *from* ace rule.");
    		/* retval = 1;  -- right now, do not fail entire transaction for non-implemented MUD actions * It's an error situation */
		}
	}

	return retval;
}


int processToAccess(char *aclName, char *aclType, AclEntry *acl, DhcpEvent *event) {
	int retval = 0;
	int actionResult = 0;
	int i, j;
	DomainResolutions *dnsInfo;
	char portRangeBuffer[PORT_BUF_SIZE];

	if (!acl) {
		logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_DEVICE_INTERFACE, "ERROR: NULL in *to* acl rule.");
		return 1;  /* It's an error situation */
	}

	for (i = 0; i < acl->aceCount; i++) {
		if (acl->aceList[i].aceType == ACLDNS) {
    		logOmsGeneralMessage(OMS_INFO, OMS_SUBSYS_DEVICE_INTERFACE, "Applying *to* dns ace rule.");

    		dnsInfo = resolveDnsEntryToIp(acl->aceList[i].dnsName);

    		// Need to check a return code to make sure the rule got applied correctly
    		installDnsRule(dnsInfo->domainName, event->ipAddress, event->macAddress, event->hostName, dnsWhiteListFile);

    		// Need to install a firewall rule for each IP that resolves
    		for (j = 0; j < dnsInfo->ipCount; j++) {
    			buildPortRange(portRangeBuffer, PORT_BUF_SIZE, &(acl->aceList[i]));
    			actionResult = installFirewallIPRule(dnsInfo->ipList[j], 					/* srcIp */
    													event->ipAddress, 					/* destIp */
														portRangeBuffer,		 			/* destPort */
														WAN_DEVICE_NAME, 					/* srcDevice - lan or wan */
														LAN_DEVICE_NAME,					/* destDevice - lan or wan */
														acl->aceList[i].protocol, 			/* protocol - tcp/udp */
														acl->aceList[i].ruleName, 			/* the name of the rule -- TODO: Better rule names by device name*/
														acl->aceList[i].actionsForwarding,	/* ACCEPT or REJECT */
														aclType,
														event->hostName						/* hostname of the new device */ );
				if (actionResult) {
					logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_DEVICE_INTERFACE, "Firewall rule installation failed");
					actionResult = 0;
					retval = 1; /* Set flag to indicate at least one firewall rule installation failed */
				}
    		}

    		freeDnsInfo(dnsInfo);
		} else {
    		logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DEVICE_INTERFACE, "Ignoring unimplemented *to* ace rule.");
    		/* retval = 1;  -- right now, do not fail entire transaction for non-implemented MUD actions * It's an error situation */
		}
	}

	return retval;
}

int executeMudWithDhcpContext(DhcpEvent *dhcpEvent)
{
	int i;
	int retval = 0; // non-zero indicates errors
	int actionResult = 0;

	logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, "IN ****NEW**** executeMudWithDhcpContext()");


	/* TODO: We need to check the return code - if this fails, we won't be able to understand the state of the device over time */
	installMudDbDeviceEntry(mudFileDataDirectory, dhcpEvent->ipAddress, dhcpEvent->macAddress,
			dhcpEvent->mudFileURL, dhcpEvent->mudFileStorageLocation, dhcpEvent->hostName);

	MudFileInfo *mudFile = parseMudFile(dhcpEvent->mudFileStorageLocation);

	// Loop over mud file and carry out actions
	if (mudFile) {
			// First, remove any prior entry for this device in case a NEW event happens for an existing configured device
			removeFirewallIPRule(dhcpEvent->ipAddress, dhcpEvent->macAddress);

			// Second, iterate over the MUD file and apply new rules
		    for (i = 0; i < mudFile->fromAccessListCount; i++) {
		    	if (!processFromAccess(mudFile->fromAccessList[i].aclName,
		    			mudFile->fromAccessList[i].aclType,
		    			getMudFileAcl(mudFile->fromAccessList[i].aclName, mudFile),
		    			dhcpEvent)) {
		    		logOmsGeneralMessage(OMS_INFO, OMS_SUBSYS_DEVICE_INTERFACE, "Successfully installed fromAccess rule.");
		    	} else {
		    		logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_DEVICE_INTERFACE, "Problems installing fromAccess rule.");
		    		retval = 1;
		    	}
		    }

		    for (i = 0; i < mudFile->toAccessListCount; i++) {
		    	if (!processToAccess(mudFile->toAccessList[i].aclName,
		    			mudFile->toAccessList[i].aclType,
		    			getMudFileAcl(mudFile->toAccessList[i].aclName, mudFile),
		    			dhcpEvent)) {
		    		logOmsGeneralMessage(OMS_INFO, OMS_SUBSYS_DEVICE_INTERFACE, "Successfully installed toAccess rule.");
		    	} else {
		    		logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_DEVICE_INTERFACE, "Problems installing toAccess rule.");
		    		retval = 1;
		    	}
		    }

		    // Install default rule to block all traffic from this IP address unless allowed in the MUD file
		    // ORDER MATTERS - this rule needs to be installed after all of the individual allow/deny rules
			actionResult = installFirewallIPRule(dhcpEvent->ipAddress, 		/* srcIp */
													"any", 					/* destIp */
													"any",		 			/* destPort */
													LAN_DEVICE_NAME, 		/* srcDevice - lan or wan */
													WAN_DEVICE_NAME,		/* destDevice - lan or wan */
													"all", 					/* protocol - tcp/udp */
													"REJECT-ALL", 			/* the name of the rule -- TODO: Better rule names by device name*/
													"DENY",					/* ACCEPT or DENY or REJECT */
													"all",
													dhcpEvent->hostName		/* hostname of the new device */ );
			if (actionResult) {
				logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_DEVICE_INTERFACE, "Problems installing default restrict rule.");
				retval = 1;
			}

			// Lastly, commit rules and restart the firewall subsystem
			if (!retval)
				commitAndApplyFirewallRules();
			else
				rollbackFirewallConfiguration();

	}
	else {
		logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_DEVICE_INTERFACE, "Problems parsing MUD file - no rules installed.");
		retval = 1;
	}

	return retval;
}

/*
 * This takes a DHCP event and performs the following:
 * 1) Validates the MUD file (maybe via yanglint when spec is finalized)
 * 2) parses the MUD file into a OSMUD data structure representing the MUD file
 * 3) Calls the device specific implementations to implement the features in the mud file
 */
void executeNewDhcpAction(DhcpEvent *dhcpEvent, int mode)
{
	int actionResult, retval = 0;
	char logMsgBuf[4096];
	buildDhcpEventContext(logMsgBuf, "NEW", dhcpEvent);
	logOmsGeneralMessage(OMS_INFO, OMS_SUBSYS_GENERAL, logMsgBuf);

	if ((dhcpEvent) && (dhcpEvent->mudFileURL))
	{
		dhcpEvent->mudSigURL = createSigUrlFromMudUrl(dhcpEvent->mudFileURL);
		dhcpEvent->mudFileStorageLocation = createStorageLocation(dhcpEvent->mudFileURL);
		dhcpEvent->mudSigFileStorageLocation = createStorageLocation(dhcpEvent->mudSigURL);

		/* We are processing a MUD aware device. Go to the MUD file server and get the usage description */
		/* non-zero return code indicates error during communications */
		/* Mud files and signature files are stored in their computed storage locations for future reference */
		if (!getOpenMudFile(dhcpEvent->mudFileURL, dhcpEvent->mudFileStorageLocation))
		{
			/* For debugging purposes only, allow the p7s verification to be optional when the "-i" option
			* is provided. This feature will be removed from a future release and is only provided now
			* until certificates compatible with OPENSSL CMS VERIFY commands are in ready use.
			*/
			if ((!getOpenMudFile(dhcpEvent->mudSigURL, dhcpEvent->mudSigFileStorageLocation))
				|| (noFailOnMudValidation))
			{

				logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_MUD_FILE, "IN ****NEW**** MUD and SIG FILE RETRIEVED!!!");

				if ((validateMudFileWithSig(dhcpEvent) == VALID_MUD_FILE_SIG)
					|| (noFailOnMudValidation))
				{
					/*
					* All files downloaded and signature valid.
					* CALL INTERFACE TO CARRY OUT MUD ACTION HERE
					*/
					executeMudWithDhcpContext(dhcpEvent);
					installMudDbDeviceEntry(mudFileDataDirectory, dhcpEvent->ipAddress, dhcpEvent->macAddress,
							dhcpEvent->mudFileURL, dhcpEvent->mudFileStorageLocation, dhcpEvent->hostName);
				}
				else
				{
					logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_MUD_FILE, "ERROR: ****NEW**** BAD SIGNATURE - FAILED VALIDATION!!!");
				}
			}
			else
			{
				logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_MUD_FILE, "ERROR: ****NEW**** NO SIG FILE RETRIEVED!!!");
			}
		}
		else
		{
			logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_MUD_FILE, "ERROR: ****NEW**** NO MUD FILE RETRIEVED!!!");
		}

	}
	else
	{

		/* This is a legacy non-MUD aware device. */
		logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_MUD_FILE, "IN ****NEW**** LEGACY DEVICE -- no mud file declared.");
		doDhcpLegacyAction(dhcpEvent);
		installMudDbDeviceEntry(mudFileDataDirectory, dhcpEvent->ipAddress, dhcpEvent->macAddress, NULL, NULL, dhcpEvent->hostName);
		
			
	}
}

void executeOldDhcpAction(DhcpEvent *dhcpEvent)
{
	char logMsgBuf[4096];
	buildDhcpEventContext(logMsgBuf, "OLD", dhcpEvent);
	logOmsGeneralMessage(OMS_INFO, OMS_SUBSYS_GENERAL, logMsgBuf);

	if (dhcpEvent)
	{
		/* TODO: Need to validate the IP address is the same as it was the last time we saw this */
		/*       If not, we need to do a remove from the device in the MUD DB file and re-add it */
	}
}

void executeDelDhcpAction(DhcpEvent *dhcpEvent)
{
	char logMsgBuf[4096];
	buildDhcpEventContext(logMsgBuf, "DEL", dhcpEvent);
	logOmsGeneralMessage(OMS_INFO, OMS_SUBSYS_GENERAL, logMsgBuf);

	if (dhcpEvent)
	{
		removeFirewallIPRule(dhcpEvent->ipAddress, dhcpEvent->macAddress);
		removeMudDbDeviceEntry(mudFileDataDirectory, dhcpEvent->ipAddress, dhcpEvent->macAddress);
		commitAndApplyFirewallRules();
	}
}


void executeOpenMudDhcpAction(DhcpEvent *dhcpEvent, int mode)
{
	if (dhcpEvent) {
		switch (dhcpEvent->action) {
			case NEW: dhcpNewEventCount++;
						executeNewDhcpAction(dhcpEvent, mode);
						break;
			case OLD: dhcpOldEventCount++;
						executeOldDhcpAction(dhcpEvent);
						break;
			case DEL: dhcpDeleteEventCount++;
						executeDelDhcpAction(dhcpEvent);
						break;
			default:
				dhcpErrorEventCount++;
				logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_GENERAL, "Bad dhcp event action code - no action taken");
		}
	}
}

DomainResolutions *resolveDnsEntryToIp(char *hostname)
{
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in *h;
    int rv;
    DomainResolutions *dnsRes = (DomainResolutions *)safe_malloc(sizeof(DomainResolutions));

    dnsRes->ipCount = 0;
    dnsRes->domainName = copystring(hostname);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;

    if ( (rv = getaddrinfo( hostname , "http" , &hints , &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return (DomainResolutions *)0;
    }

    // loop through all the results and add each to the list
    for(p = servinfo; p != NULL; p = p->ai_next)
    {
        h = (struct sockaddr_in *) p->ai_addr;
        dnsRes->ipList[dnsRes->ipCount++] = copystring(inet_ntoa(h->sin_addr));
    }

    freeaddrinfo(servinfo); // all done with this structure

    return dnsRes;
}

void freeDnsInfo(DomainResolutions *dnsInfo) {

}

/*
	x509 methods
*/

void on_connect(struct mosquitto *mosq, void *obj, int rc) {
    
    if(rc == 0) {
        printf("Connected to broker.\n");
        mosquitto_subscribe(mosq, NULL, "certificates/#", 0);
    } else {
        printf("Failed to connect, return code %d\n", rc);
    }
}

char *info_detection(char *command, char *extension) {
    // Executes the command to retrieve the MUD URL from the certificate
    char *result = NULL;
    size_t buffer_size = 64; 
    result = (char*)malloc(buffer_size); 

    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        free(result); // Free allocated memory
        return NULL;
    }

    if (fgets(result, buffer_size, fp) == NULL) {
        free(result); // Free allocated memory
        pclose(fp);
        return NULL;
    }

    pclose(fp);

    // Remove trailing newline if present
    char *newline = strchr(result, '\n');
    if (newline) {
        *newline = '\0';
    }

    return result; 

}

char *clean_string(char *str){
    if (str[0] == '.' && str[1] == '"') {
        memmove(str, str + 2, strlen(str) - 1);
    }

    return str;

}

char *extract_info(char *x509_cert) {
    // Executes the command to retrieve the MUD URL from the certificate
	char *combined = (char*)malloc(256);
    char command[512];
    snprintf(command, sizeof(command), "openssl x509 -in %s -noout -text | grep -A1 %s | tail -n1 | awk '{$1=$1;print}'", x509_cert, mudurl_extension);

    // Stores the MUD URL in a variable
    char *mudurl = info_detection(command, mudurl_extension);
    if(mudurl != NULL) {
        mudurl = clean_string(mudurl);
        printf("Extracted MUD URL: %s\n", mudurl);
    } else {
        printf("Unable to extract MUD URL. The device could be not MUD-aware, or the id-pe-mud-url extension was not added to the certificate.\n");
    }

    // Executes the command to retrieve the MUD signer from the certificate
    snprintf(command, sizeof(command), "openssl x509 -in %s -noout -text | grep -A1  %s| tail -n1 | awk '{$1=$1;print}'", x509_cert, mudsigner_extension);
    char *mudsigner = info_detection(command, mudsigner_extension);
    if(mudsigner == NULL) {
        printf("Unable to extract MUD signer. The device could be not MUD-aware, or the id-pe-mud-signer extension was not added to the certificate.\n");
    }
    else {
        mudsigner = clean_string(mudsigner);
        printf("Extracted MUD signer: %s\n", mudsigner);
    }
	
	// contatenate mudurl and mudsigner, separated by a comma
	combined = (char*)malloc(strlen(mudurl) + strlen(mudsigner) + 2);
	
	if (mudurl != NULL && mudsigner != NULL) {
		if (combined != NULL) {
			sprintf(combined, "%s,%s", mudurl, mudsigner);
		} else {
			fprintf(stderr, "Memory allocation failed for combined string.\n");
			combined = NULL;
		}
	}
     // Free allocated memory
    free(mudurl);
    free(mudsigner); 

	return combined;
}

void *manage_certificate(DhcpEvent *dhcpEvent) {
    char *certificate = (char *)dhcpEvent->mudFileURL;
	printf("Certificate: %s\n", certificate);
    // Write the certificate to a file
    char *subtopic = strrchr(topic, '/') + 1;
    char *filename = strcat(subtopic, ".pem");
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file %s\n", filename);
        return NULL;
    }
    fprintf(file, "%s", certificate);
    fclose(file);

    // Checks the chain of trust of the certificate
    char command[512];
	char *res = NULL;
    bool valid = false;
    snprintf(command, sizeof(command), "openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt %s", filename);
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error: Failed to run command.\n");
        return NULL;
    }

    char result[128];
    if (fgets(result, sizeof(result), fp) != NULL) {
        if (strstr(result, "OK") != NULL) {
            valid = true;
        } else {
            valid = false;
        }
    } else {
        valid = false;
    }

    pclose(fp);

    if (valid) {
        printf("Certificate is valid.\n");
        res = extract_info(filename);
		if (res != NULL) {
			char *mudurl = strtok(res, ",");
			char *mudsigner = strtok(NULL, ",");

			if (mudurl != NULL && mudsigner != NULL) {
			printf("MUD URL: %s\n", mudurl);
			printf("MUD Signer: %s\n", mudsigner);
			dhcpEvent->mudFileURL = strdup(mudurl);

			// Execute the MUD file
			// Same process as DHCP
			dhcpEvent->mudSigURL = createSigUrlFromMudUrl(dhcpEvent->mudFileURL);
			dhcpEvent->mudFileStorageLocation = createStorageLocation(dhcpEvent->mudFileURL);
			dhcpEvent->mudSigFileStorageLocation = createStorageLocation(dhcpEvent->mudSigURL);

			/* We are processing a MUD aware device. Go to the MUD file server and get the usage description */
			/* non-zero return code indicates error during communications */
			/* Mud files and signature files are stored in their computed storage locations for future reference */
			if (!getOpenMudFile(dhcpEvent->mudFileURL, dhcpEvent->mudFileStorageLocation))
			{
				/* For debugging purposes only, allow the p7s verification to be optional when the "-i" option
				* is provided. This feature will be removed from a future release and is only provided now
				* until certificates compatible with OPENSSL CMS VERIFY commands are in ready use.
				*/
				if ((!getOpenMudFile(dhcpEvent->mudSigURL, dhcpEvent->mudSigFileStorageLocation)) || (noFailOnMudValidation))
				{

					logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_MUD_FILE, "IN ****NEW**** MUD and SIG FILE RETRIEVED!!!");

					if ((validateMudFileWithSig(dhcpEvent) == VALID_MUD_FILE_SIG) || (noFailOnMudValidation))
					{
						/*
						* All files downloaded and signature valid.
						* CALL INTERFACE TO CARRY OUT MUD ACTION HERE
						*/
						executeMudWithDhcpContext(dhcpEvent);
						installMudDbDeviceEntry(mudFileDataDirectory, dhcpEvent->ipAddress, dhcpEvent->macAddress,
								dhcpEvent->mudFileURL, dhcpEvent->mudFileStorageLocation, dhcpEvent->hostName);
					}
					else
					{
						logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_MUD_FILE, "ERROR: ****NEW**** BAD SIGNATURE - FAILED VALIDATION!!!");
					}
				}
				else
				{
					logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_MUD_FILE, "ERROR: ****NEW**** NO SIG FILE RETRIEVED!!!");
				}
			}


			free(res);


			}
		}
    } else {
        printf("Certificate is not valid.\n");
    }

	free(res);
	free(filename);
	free(certificate);
	free(subtopic);
	
	return NULL;
}


void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg, DhcpEvent *dhcpEvent) {
    pthread_t thread;
    char *message = NULL;
	message = strdup((char *)msg->payload);
    if (message == NULL) {
        fprintf(stderr, "Error: Out of memory.\n");
        return;
    }

	dhcpEvent->mudFileURL = strdup(message);
    topic = strdup(msg->topic);
    printf("Message arrived on topic: %s\n", topic);
    pthread_create(&thread, NULL, manage_certificate, dhcpEvent);
    pthread_detach(thread);

	free(message);
	free(topic);
	free(dhcpEvent);
}


int x509_routine(DhcpEvent *dhcpEvent) {
    struct mosquitto *mosq;
    int rc;
	int retval = 0;

    mosquitto_lib_init();

    mosq = mosquitto_new("subscriber-client", true, NULL);
    if(!mosq) {
        fprintf(stderr, "Error: Out of memory.\n");
        return 1;
    }

    mosquitto_connect_callback_set(mosq, on_connect);
    mosquitto_message_callback_set(mosq, on_message);

    rc = mosquitto_connect(mosq, "mqttbroker", 1883, 60);
    if(rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Unable to connect (%d).\n", rc);
        return 1;
    }

    mosquitto_loop_start(mosq);

    

    // Wait for a message to be received
    printf("Press Enter to exit...\n");
    getchar();

    // Cleanup
    mosquitto_loop_stop(mosq, true);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();

	return retval;

}

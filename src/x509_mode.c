#include <mosquitto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "dhcp_event.h"
#include "mud_manager.h"
#include "mudparser.h"


char message_buffer[256];
pthread_mutex_t message_mutex = PTHREAD_MUTEX_INITIALIZER;
char *topic;
char *mudurl_extension = "1.3.6.1.5.5.7.1.25";
char *mudsigner_extension = "1.3.6.1.5.5.7.1.30";
DhcpEvent dhcpEventPriv;


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

char *clean_string(char *str) {
    if (str[0] == '.' && (str[1] == '"' || str[1] == '.')) {
        memmove(str, str + 2, strlen(str) - 1);
    }

    return str;
}


void extract_info(char *x509_cert) {
    // Executes the command to retrieve the MUD URL from the certificate
    char command[512];
    int rescurl = 0;
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

    printf("Retrieving MUD file...\n");

    // Update the internal dhcp data structure with the mudurl
    dhcpEventPriv.mudFileURL = mudurl;
    dhcpEventPriv.mudsigner = mudsigner;

    executeOpenMudDhcpAction(&dhcpEventPriv, 1);



     // Free allocated memory
    free(mudurl);
    free(mudsigner); 
}

void *manage_certificate(void *msg) {
    char *certificate = (char *)msg;

    // Write the certificate to a file
    char *filename = strrchr(topic, '/') + 1;
    filename = strcat(filename, ".pem");
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file %s\n", filename);
        return NULL;
    }
    fprintf(file, "%s", certificate);
    fclose(file);

    // Checks the chain of trust of the certificate
    char command[512];
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
        extract_info(filename);
    } else {
        printf("Certificate is not valid.\n");
    }
}


void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg) {
    pthread_t thread;
    char *message = strdup((char *)msg->payload);
    if (message == NULL) {
        fprintf(stderr, "Error: Out of memory.\n");
        return;
    }

    topic = strdup(msg->topic);
    printf("Message arrived on topic: %s\n", topic);
    pthread_create(&thread, NULL, manage_certificate, message);
    pthread_detach(thread);
}


int x509_routine(DhcpEvent *dhcpEvent) {
    struct mosquitto *mosq;
    int rc;

    // Initialize the x509_mode's internal dhcp data structure with the value that was passed in
    // so that this can be a global variable seen by all functions in this file
    dhcpEventPriv = *dhcpEvent;

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

    return 0;
}

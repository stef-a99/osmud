#include <mosquitto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "comms.h"

char message_buffer[256];
pthread_mutex_t message_mutex = PTHREAD_MUTEX_INITIALIZER;
char *topic;
char *mudurl_extension = "1.3.6.1.5.5.7.1.25";
char *mudsigner_extension = "1.3.6.1.5.5.7.1.30";



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


char *extract_info(char *x509_cert) {
    // Executes the command to retrieve the MUD URL from the certificate
    char command[512];
    char *combined_info = NULL;
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

    if (mudurl != NULL && mudsigner != NULL) {
        
        snprintf(combined_info, sizeof(combined_info), "%s,%s", mudurl, mudsigner);
        printf("Combined MUD URL and signer: %s\n", combined_info);
    }
    else {
        combined_info = NULL;
    }


     // Free allocated memory
    free(mudurl);
    free(mudsigner); 

    return combined_info;
}

void *manage_certificate(void *msg) {
    char *certificate = (char *)msg;
    char *subtopic = strrchr(topic, '/') + 1; 
    char *filename = malloc(strlen(subtopic) + 5); // Allocate memory for filename
    if (filename == NULL) {
        fprintf(stderr, "Error: Out of memory.\n");
        return NULL;
    }
    strcpy(filename, subtopic); 
    strcat(filename, ".pem"); 

    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file %s\n", filename);
        free(filename); // Free allocated memory
        return NULL;
    }
    fprintf(file, "%s", certificate);
    fclose(file);

    // Checks the chain of trust of the certificate
    char command[512];
    char *combined_info = NULL;
    bool valid = false;
    int retval = 0;
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
        combined_info = extract_info(filename);
        int rescurl = 0;

        if (combined_info != NULL) {
            // Allocate memory for combined MUD URL and signer
            size_t combined_info_size = strlen(combined_info) + 2; 
            char *mudurl = malloc(combined_info_size);
            char *mudsigner = malloc(combined_info_size);
            if (mudurl == NULL || mudsigner == NULL) {
                fprintf(stderr, "Error: Out of memory.\n");
                free(combined_info);
                free(filename);
                return NULL;
            }

            // Copy tokens using strtok (consider alternative parsing if thread-safety is crucial)
            char *tmp_info = strdup(combined_info);
            strcpy(mudurl, strtok(tmp_info, ","));
            strcpy(mudsigner, strtok(NULL, ","));
            free(tmp_info);

            if (mudurl != NULL && mudsigner != NULL) {
                printf("MUD URL: %s\n", mudurl);
                printf("MUD Signer: %s\n", mudsigner);

                // Curlata al server MUD
                rescurl = getOpenMudFile(mudurl, "mudfile.json");

                free(mudurl);
                free(mudsigner);
            } else {
                printf("Error: Failed to parse combined MUD URL and signer.\n");
            }

            free(combined_info); 
        } else {
            printf("Failed to extract MUD URL and signer.\n");
        }

        free(filename); // Free filename memory
    } else {
        printf("Certificate is not valid.\n");
    }

    return NULL;
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


int x509_routine() {
    struct mosquitto *mosq;
    int rc;

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

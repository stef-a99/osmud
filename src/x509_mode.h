#ifndef _MQTT_SUBSCRIBER_H_
#define _MQTT_SUBSCRIBER_H_

// Include necessary headers
#include <mosquitto.h>
#include <pthread.h>

// Function prototypes
int x509_routine();
void on_connect(struct mosquitto *mosq, void *obj, int rc);
void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg);
void *manage_certificate(void *msg);
char *info_detection(char *command, char *extension);
void extract_info(char *x509_cert);


// Global variables (consider making these more encapsulated if needed)
extern char message_buffer[256];
extern pthread_mutex_t message_mutex;
extern char *topic;
extern char *mudurl_extension;
extern char *mudsigner_extension;

#endif // _MQTT_SUBSCRIBER_H_
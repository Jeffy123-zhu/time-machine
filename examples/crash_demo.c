// crash_demo.c
// Demonstration program for eBPF Time Machine
// 
// This program intentionally contains a use-after-free bug
// to showcase how Time Machine can help debug crashes

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define REQUEST_DATA_SIZE 1024

typedef struct {
    int id;
    char *data;
    size_t size;
    time_t timestamp;
} request_t;

// Process a single request
void process_request(int request_id) {
    time_t now = time(NULL);
    printf("[%ld] Processing request #%d\n", now, request_id);
    
    // Allocate request structure
    request_t *req = malloc(sizeof(request_t));
    if (!req) {
        fprintf(stderr, "Failed to allocate request\n");
        return;
    }
    
    // Initialize request
    req->id = request_id;
    req->size = REQUEST_DATA_SIZE;
    req->timestamp = now;
    
    // Allocate data buffer
    req->data = malloc(req->size);
    if (!req->data) {
        fprintf(stderr, "Failed to allocate data buffer\n");
        free(req);
        return;
    }
    
    // Fill with some data
    snprintf(req->data, req->size, 
             "Request #%d data - timestamp: %ld", 
             request_id, now);
    
    // Simulate some processing
    usleep(50000);  // 50ms
    
    // Here's the bug!
    // On request #42, we'll free everything early
    if (request_id == 42) {
        printf("  [DEBUG] Request #42 - special handling...\n");
        
        // Free the memory (BUG: we'll try to use it later!)
        free(req->data);
        free(req);
        
        // Wait a bit to make it obvious in the trace
        sleep(1);
        
        printf("  [DEBUG] Accessing data...\n");
        
        // NOW THE CRASH: use-after-free!
        // Time Machine will catch this and show exactly what happened
        printf("  Data content: %s\n", req->data);  // BUG: use-after-free!
        
        // We'll never get here
        printf("  Request complete\n");
        
    } else {
        // Normal path - proper cleanup
        printf("  Data: %s\n", req->data);
        free(req->data);
        free(req);
        printf("[%ld] Request #%d completed\n", now, request_id);
    }
}

int main(int argc, char **argv) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════╗\n");
    printf("║         eBPF Time Machine - Demo App             ║\n");
    printf("╚═══════════════════════════════════════════════════╝\n");
    printf("\n");
    
    printf("PID: %d\n", getpid());
    printf("\n");
    printf("This program will crash at request #42\n");
    printf("Use eBPF Time Machine to find out why!\n");
    printf("\n");
    printf("In another terminal, run:\n");
    printf("  sudo ./timemachine record %d\n", getpid());
    printf("\n");
    
    // Give user time to start the tracer
    printf("Starting in 3 seconds...\n");
    sleep(3);
    
    printf("\n");
    printf("──────────────────────────────────────────────────────\n");
    printf("Starting request processing...\n");
    printf("──────────────────────────────────────────────────────\n");
    printf("\n");
    
    // Process 50 requests
    // Request #42 will trigger the bug
    for (int i = 1; i <= 50; i++) {
        process_request(i);
        
        // Small delay between requests
        usleep(100000);  // 100ms
        
        // We'll crash on request #42, so we won't reach here
        if (i == 42) {
            // If we get here, something's wrong with our bug! 😅
            printf("ERROR: We should have crashed!\n");
            break;
        }
    }
    
    printf("\n");
    printf("All requests completed successfully!\n");
    printf("(This message should never appear due to the crash)\n");
    
    return 0;
}

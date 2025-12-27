/**
 * @file pam_secreg.c
 * @brief PAM module for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SECREG_SOCKET "/run/secreg/socket"
#define BUFFER_SIZE 4096

static int authenticate_via_socket(pam_handle_t *pamh, 
                                    const char *username,
                                    const char *password) {
    int sockfd;
    struct sockaddr_un addr;
    char buffer[BUFFER_SIZE];
    ssize_t n;
    
    // Create socket
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to create socket: %m");
        return PAM_AUTH_ERR;
    }
    
    // Set up address
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SECREG_SOCKET, sizeof(addr.sun_path) - 1);
    
    // Connect to daemon
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to connect to secregd: %m");
        close(sockfd);
        return PAM_AUTH_ERR;
    }
    
    // Send authentication request
    snprintf(buffer, sizeof(buffer), 
             "AUTH %s %s\n", username, password);
    n = write(sockfd, buffer, strlen(buffer));
    if (n < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to send auth request: %m");
        close(sockfd);
        return PAM_AUTH_ERR;
    }
    
    // Read response
    n = read(sockfd, buffer, sizeof(buffer) - 1);
    if (n <= 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to receive auth response: %m");
        close(sockfd);
        return PAM_AUTH_ERR;
    }
    buffer[n] = '\0';
    
    close(sockfd);
    
    // Check response
    if (strncmp(buffer, "OK", 2) == 0) {
        return PAM_SUCCESS;
    }
    
    pam_syslog(pamh, LOG_WARNING, "Authentication failed for user: %s", username);
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, 
                                    int argc, const char **argv) {
    const char *username;
    const char *password;
    int ret;
    
    // Get username
    ret = pam_get_user(pamh, &username, "Username: ");
    if (ret != PAM_SUCCESS) {
        return ret;
    }
    
    if (!username || !*username) {
        pam_syslog(pamh, LOG_ERR, "No username provided");
        return PAM_AUTH_ERR;
    }
    
    // Get password
    ret = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (ret != PAM_SUCCESS) {
        return ret;
    }
    
    if (!password || !*password) {
        pam_syslog(pamh, LOG_ERR, "No password provided");
        return PAM_AUTH_ERR;
    }
    
    // Authenticate via socket
    ret = authenticate_via_socket(pamh, username, password);
    
    // Clear password from memory
    if (password) {
        memset((void *)password, 0, strlen(password));
    }
    
    return ret;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, 
                               int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, 
                                 int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, 
                                    int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, 
                                     int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, 
                                 int argc, const char **argv) {
    return PAM_SUCCESS;
}

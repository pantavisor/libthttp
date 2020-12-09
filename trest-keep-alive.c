
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "trest.h"

const char** pv_ph_get_certs()
{
        struct dirent **files;
        char **cafiles;
        char *dir = "./certs/";
        char path[128];
        int n = 0, i = 0, size = 0;

        n = scandir(dir, &files, NULL, alphasort);
        if (n < 0)
                return NULL;

        // Always n-1 due to . and .., and need one extra
        cafiles = calloc(1, (sizeof(char*) * (n-1)));

        while (n--) {
                if (!strncmp(files[n]->d_name, ".", 1))
                        continue;

                sprintf(path, "%s%s", dir, files[n]->d_name);
                size = strlen(path);
                cafiles[i] = malloc((size+1) * sizeof(char));
                strncpy(cafiles[i], path, size);
                cafiles[i][size] = '\0';
                i++;
                free(files[n]);
        }

        free(files);

        return (const char **) cafiles;
}



int main(int argc, char **argv) {

	struct sockaddr sockaddr;
	trest_auth_status_enum status;
	const char **cacerts = pv_ph_get_certs();

	trest_ptr client = trest_new_tls_from_userpass("api.pantahub.com", 443,
						       "asacasa",
						       "t3st!234",
						       cacerts,
						       "Libthttp examples",
						       &sockaddr);



	for (int i = 0; i < 50; i++) {

		status = trest_update_auth(client);

		if (status != TREST_AUTH_STATUS_OK) {
			printf("ERROR: trest_update_auth must succees; but status is %d\n", status);
			return 1;
		}
	
		trest_request_ptr req =
			trest_make_request (TREST_METHOD_GET,
					    "https://api2.pantahub.com/auth_status",
					    NULL,
					    NULL,
					    NULL);

		trest_response_ptr res =
			trest_do_json_request (client,
					       req);
		trest_response_free(res);
		trest_request_free(req);
	}
		
	return 0;
}

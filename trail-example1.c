#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trail.h"

const char BUF[] =
	"{"
	"  \"rev\": 100,"
	"  \"systemc\":"
	"    ["
	"      {"
	"        \"key\": \"0base.cpio.gz\","
	"        \"value\": \"57f4e1f0c094f6221a000031\""
	"      }"
	"    ]"
	"  ,"
	"  \"volumes\": ["
	"    {"
	"      \"key\": \"openwrt-malta-be-root.squashfs\","
	"      \"value\": {"
	"        \"type\": \"rw\","
	"        \"file\": \"57ec1448c094f65d5d000012\""
	"      }"
	"    },"
	"    {"
	"      \"key\": \"writable.ext4\","
	"      \"value\": {"
	"        \"type\": \"rw\","
	"        \"file\": \"57ee59eec094f67e2d000003\""
	"      }"
	"    }"
	"  ],"
	"  \"platforms\": {"
	"    \"owrt\": {"
	"      \"type\": \"lxc\","
	"      \"parent\": null,"
	"      \"configs\": ["
	"        {"
	"          \"key\": \"lxc.conf\","
	"          \"value\": \"57ec1452c094f65d5d000014\""
	"        },"
	"        {"
	"          \"key\": \"openwrt.common.conf\","
	"          \"value\": \"57ec1453c094f65d5d000015\""
	"        }"
	"      ],"
	"      \"exec\": \"/sbin/init\","
	"      \"share\": ["
	"        \"NETWORK\","
	"        \"UTS\","
	"        \"IPC\""
	"      ]"
	"    }"
	"  },"
	"  \"kernel\": {"
	"    \"key\": \"kernel.img\","
	"    \"value\": \"57f4e1efc094f6221a000030\""
	"  }"
	"}";

int main ()
{
	systemc_state *state = trail_parse_state (BUF, strlen(BUF));
	systemc_object **basev_i = state->basev;
	systemc_volobject **volumesv_i = state->volumesv;
	systemc_platform **platformsv_i = state->platformsv;

	printf("systemc_state:\n");
	printf(" rev: %d\n", state->rev);

	printf(" kernel:\n");
	printf ("  - abrn:%s filename:%s\n", state->kernel->abrn, state->kernel->filename);

	printf(" systemc:\n");
	while(*basev_i) {
		printf ("  - abrn:%s filename:%s\n", (*basev_i)->abrn, (*basev_i)->filename);
		basev_i++;
	}

	printf(" volumes:\n");
	while(*volumesv_i) {
		printf ("  - abrn:%s filename:%s flags:%s \n",
			(*volumesv_i)->abrn, (*volumesv_i)->filename, (*volumesv_i)->flags);
		volumesv_i++;
	}

	printf(" platforms:\n");
	while(*platformsv_i) {
		systemc_object **configs_i;

		printf ("  - name:%s type: %s  parent: %s  exec: %s  share: %d\n",
			(*platformsv_i)->name, (*platformsv_i)->type, (*platformsv_i)->parent,
			(*platformsv_i)->exec, (*platformsv_i)->share);

		configs_i = (*platformsv_i)->configs;

		printf ("    configs:\n");
		while (*configs_i) {
			printf ("      - abrn:%s filename:%s\n", (*configs_i)->abrn, (*configs_i)->filename);
			configs_i++;
		}

		platformsv_i++;
	}
	trail_state_free (state);
	return 0;
}

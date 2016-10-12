
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trail.h"

const char BUF[] =
	"{"
	"  \"rev\": 100,"
	"  \"systemc\": ["
	"    ["
	"      {"
	"        \"key\": \"0base.cpio.gz\","
	"        \"value\": \"57f4e1f0c094f6221a000031\""
	"      }"
	"    ]"
	"  ],"
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

	printf("systemc_state:\n");
	printf(" - rev: %d\n", state->rev);
	free(state);
	return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hs.h"
#include "ch.h"

#define PAYLOAD "ccccccawef232werbddddddd"
#define REG_PATTERN "a.*b"
#define COMPILE_FLAGS CH_FLAG_CASELESS|CH_FLAG_DOTALL|CH_FLAG_SINGLEMATCH 

ch_callback_t MatchHandler(unsigned int id, unsigned long long from,
                            unsigned long long to, unsigned int flags,
                            unsigned int size, const ch_capture_t *captured,
                            void *ctx)
{
	const char *pattern = (const char*)ctx;
	int i = from;

	printf("Match from [%d] to [%d]!\nSubstring:[", from, to);
	for( ; i < to; i++)
	{
		printf("%c", pattern[i]);
	}
	printf("]\n");

	return CH_CALLBACK_TERMINATE;
}

ch_callback_t ErrorHandler(ch_error_event_t error_type,unsigned int id, void *info,void *ctx)
{
	printf("Scan Error occured. Terminate!\n");

	return CH_CALLBACK_TERMINATE;
}

int chimera_engine_test()
{
    ch_error_t err = 0;
    ch_scratch_t *scratch = NULL;
	ch_compile_error_t *errReason = NULL;
	hs_platform_info_t platform;
	ch_database_t *db = NULL;
	char pattern[] = {REG_PATTERN};

	platform.cpu_features = HS_CPU_FEATURES_AVX2;
	err = ch_compile(pattern, COMPILE_FLAGS, CH_MODE_NOGROUPS, &platform, &db, &errReason);
	if( err == CH_COMPILER_ERROR )
	{
		printf("Compile pattern [%s] failed, reason [%s]!\n", pattern, errReason->message);
		goto OUT;
	}

    err = ch_alloc_scratch(db, &scratch);
    if (err != CH_SUCCESS)
	{
        printf("Alloc scratch failed!");
		goto OUT;
    }

	err = ch_scan(db, PAYLOAD, strlen(PAYLOAD), 0, scratch, MatchHandler, ErrorHandler, (void*)PAYLOAD);
	if( err != CH_SUCCESS )
	{
		goto OUT;
	}

OUT:
	if( scratch )
	{
    	ch_free_scratch(scratch);
	}
	if( errReason )
	{
		ch_free_compile_error(errReason);
	}

	return err;
}

int main(int argc, char *argv[])
{
	chimera_engine_test();

	return 0;
}


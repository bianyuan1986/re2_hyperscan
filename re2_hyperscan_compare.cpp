#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "re2/re2.h"

#include "hs.h"
#include "hs_common.h"


using namespace std;

#define EXECUTION_COUNT 50

enum
{
	TARGET_ALL = 0,
	TARGET_ARG = 1,
	TARGET_BODY = 2,
	TARGET_CGI = 3,
	TARGET_CGI_FULL = 4,
	TARGET_CLIENT_IP = 5,
	TARGET_HEAD = 6,
	TARGET_CONTENT_TYPE = 7,
	TARGET_PROXY = 8,
	TARGET_ACCEPT = 9,
	TARGET_COOKIE = 10,
	TARGET_IF = 11,
	TARGET_RANGE = 12,
	TARGET_REFERER = 13,
	TARGET_USER_AGENT = 14,
	TARGET_HOST = 15,
	TARGET_UPLOAD_CNT = 16,
	TARGET_UPLOAD_FILENAME = 17,
	TARGET_UPLOAD_LINE = 18,
	TARGET_MAX
};

const char *TargetName[TARGET_MAX] =
{
	[TARGET_ALL] = "all",
	[TARGET_ARG] = "arg",
	[TARGET_BODY] = "body",
	[TARGET_CGI] = "cgi",
	[TARGET_CGI_FULL] = "cgi_full",
	[TARGET_CLIENT_IP] = "client_ip",
	[TARGET_HEAD] = "head",
	[TARGET_CONTENT_TYPE] = "head_key#Content-Type",
	[TARGET_PROXY] = "head_key#Proxy",
	[TARGET_ACCEPT] = "head_key#accept",
	[TARGET_COOKIE] = "head_key#cookie",
	[TARGET_IF] = "head_key#if",
	[TARGET_RANGE] = "head_key#range",
	[TARGET_REFERER] = "head_key#referer",
	[TARGET_USER_AGENT] = "head_key#user-agent",
	[TARGET_HOST] = "host",
	[TARGET_UPLOAD_CNT] = "upload_cnt",
	[TARGET_UPLOAD_FILENAME] = "upload_filename",
	[TARGET_UPLOAD_LINE] = "upload_line",
};

struct matchRule
{
	int cnt;
	int cur;
	int id[20];
};

struct result
{
	double re2TimeConsumed;
	double hsTimeConsumed;
};

struct engine
{
	RE2 *re2Engine;

	hs_database_t *hsEngine;
	hs_scratch_t *scratch;

	int reFailed;
	int hsFailed;
};

struct rule
{
	char *pattern;
	int len;
	int id;

	struct engine e;
	struct result res;
};

struct ruleSet
{
	int target;
	int cnt;
	int cur;
	struct rule *r;

	/*concatenate multi-rule using '|' character*/
	char *ruleSetPattern;
	int len;
	/*hyperscan single pattern match engine*/
	struct engine e;
	struct result res;

	/*multi pattern for multiE*/
	unsigned int *ids;
	unsigned int *flags;
	const char **multiPattern;
	/*hyperscan multi-pattern match engine*/
	struct engine multiE;
	struct result multiRes;
	struct matchRule outcome;
};

int debug = 0;
int ruleCnt[TARGET_MAX] = {0};
struct ruleSet ruleSetArray[TARGET_MAX];
RE2::Options opt;
hs_platform_info_t platform;

const char *payload = "GET / HTTP/1.1\r\nHost: www.testtang4.com\r\nstgw-dstip: 10.10.10.10\r\nConnection: Keep-Alive\r\nAccept: text/plain\r\nContent-Type: application/x-www-form-urlencoded\r\nReferer: http://www.123.com\r\nContent-Length: 1021\r\nstgw-orgreq: POST /menshen?id= HTTP/1.1\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022)\r\nstgw-srcip: 9.9.9.9\r\nX-Forwarded-For: 3.3.3.3\r\n\r\ntitle=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2&sub%5B%5D=3&title=test&sub%5B%5D=1&sub%5B%5D=2abcsdfwefwbcd";

int getTargetIdx(char *target)
{
	int i = 0;

	for( ; i < TARGET_MAX; i++)
	{
		if( strcasecmp(target, TargetName[i]) == 0 )
		{
			return i;
		}
	}

	return -1;
}

extern "C" int search_all_re2(void* obj, const char* subject, int subject_len)
{
	re2::StringPiece input(subject, subject_len);
	re2::StringPiece result;
	int found = 0;

	/*
	while (RE2::FindAndConsume(&input, *(RE2*)obj)) {
		found++;
        break;
	}
	*/
	found = RE2::PartialMatch(input, *(RE2*)obj);
	/*
	if( found )
	{
		printf("RE2 FOUND!\n");
	}
	*/

	return found;
}

extern "C" void test_re2()
{
	int i = 0;
	int j = 0;
	int cnt = 0;
	int pLen = 0;
	struct ruleSet *set = NULL;
	struct rule *r = NULL;
	struct timeval t1;
	struct timeval t2;

	pLen = strlen(payload);
	for( ; i < TARGET_MAX; i++)
	{
		set = &ruleSetArray[i];
		for( j = 0; j < set->cnt; j++)
		{
			r = &(set->r[j]);
			if( (r->e.re2Engine == NULL) || (r->e.reFailed == 1) )
			{
				r->res.re2TimeConsumed = 0.0; 
				continue;
			}
			gettimeofday(&t1, NULL);
			for( cnt = 0; cnt < EXECUTION_COUNT; cnt++)
			{
				search_all_re2(r->e.re2Engine, payload, pLen);
			}
			gettimeofday(&t2, NULL);
			r->res.re2TimeConsumed = (t2.tv_sec - t1.tv_sec)*1000000 + (t2.tv_usec-t1.tv_usec);
		}

		if( (set->e.re2Engine == NULL) || (set->e.reFailed == 1) )
		{
			set->res.re2TimeConsumed = 0.0;
			continue;
		}
		//printf("RE2 scan:%-20s\n", TargetName[i]);
		gettimeofday(&t1, NULL);
		for( cnt = 0; cnt < EXECUTION_COUNT; cnt++)
		{
			search_all_re2(set->e.re2Engine, payload, pLen);
		}
		gettimeofday(&t2, NULL);
		set->res.re2TimeConsumed = (t2.tv_sec - t1.tv_sec)*1000000 + (t2.tv_usec-t1.tv_usec);
	}
}

extern "C" int match_handler(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *context)
{
	//printf("HS FOUND!\n");
	return 1;
}

extern "C" int multi_match_handler(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *context)
{
	struct matchRule *outcome = NULL;

	outcome = (struct matchRule*)context;
	outcome->id[outcome->cur] = id;
	outcome->cur++;

	if( outcome->cur >= outcome->cnt )
	{
		return 1;
	}

	return 0;
}

extern "C" void test_hyperscan()
{
	int i = 0;
	int j = 0;
	int cnt = 0;
	int pLen = 0;
	hs_error_t ret = 0;
	struct ruleSet *set = NULL;
	struct rule *r = NULL;
	struct timeval t1;
	struct timeval t2;

	pLen = strlen(payload);
	for( ; i < TARGET_MAX; i++)
	{
		set = &ruleSetArray[i];
		for( j = 0; j < set->cnt; j++)
		{
			r = &(set->r[j]);
			if( (r->e.hsEngine == NULL) || (r->e.hsFailed == 1) )
			{
				r->res.hsTimeConsumed = 0.0; 
				continue;
			}
			gettimeofday(&t1, NULL);
			for( cnt = 0; cnt < EXECUTION_COUNT; cnt++)
			{
				ret = hs_scan(r->e.hsEngine, payload, pLen, 0, r->e.scratch, match_handler, NULL);
			}
			gettimeofday(&t2, NULL);
			r->res.hsTimeConsumed = (t2.tv_sec - t1.tv_sec)*1000000 + (t2.tv_usec-t1.tv_usec);
		}

		if( (set->e.hsEngine == NULL) || (set->e.hsFailed == 1) )
		{
			set->res.hsTimeConsumed = 0.0; 
			continue;
		}
		gettimeofday(&t1, NULL);
		for( cnt = 0; cnt < EXECUTION_COUNT; cnt++)
		{
			ret = hs_scan(set->e.hsEngine, payload, pLen, 0, set->e.scratch, match_handler, NULL);
		}
		gettimeofday(&t2, NULL);
		set->res.hsTimeConsumed = (t2.tv_sec - t1.tv_sec)*1000000 + (t2.tv_usec-t1.tv_usec);

		if( (set->multiE.hsEngine == NULL) || (set->multiE.hsFailed == 1) )
		{
			set->multiRes.hsTimeConsumed = 0.0; 
			continue;
		}
		gettimeofday(&t1, NULL);
		for( cnt = 0; cnt < EXECUTION_COUNT; cnt++)
		{
			set->outcome.cnt = 20;
			set->outcome.cur = 0;
			ret = hs_scan(set->multiE.hsEngine, payload, pLen, 0, set->multiE.scratch, multi_match_handler, &(set->outcome));
		}
		gettimeofday(&t2, NULL);
		set->multiRes.hsTimeConsumed = (t2.tv_sec - t1.tv_sec)*1000000 + (t2.tv_usec-t1.tv_usec);
	}
}

extern "C" void clean()
{
	int i = 0;
	int j = 0;
	struct ruleSet *set = NULL;
	struct rule *r = NULL;

	for( ; i < TARGET_MAX; i++)
	{
		set = &ruleSetArray[i];
		for( j = 0; j < set->cnt; j++)
		{
			r = &(set->r[j]);
			if( r->e.hsEngine )
			{
				hs_free_database(r->e.hsEngine);
				r->e.hsEngine = NULL;
			}
			if( r->e.scratch )
			{
				hs_free_scratch(r->e.scratch);
				r->e.scratch = NULL;
			}
			if( r->e.re2Engine )
			{
				delete r->e.re2Engine;
				r->e.re2Engine = NULL;
			}
			if( r->pattern )
			{
				free(r->pattern);
			}
		}

		if( set->e.hsEngine )
		{
			hs_free_database(set->e.hsEngine);
			set->e.hsEngine = NULL;
		}
		if( set->e.scratch )
		{
			hs_free_scratch(set->e.scratch);
			set->e.scratch = NULL;
		}
		if( set->e.re2Engine )
		{
			delete set->e.re2Engine;
			set->e.re2Engine = NULL;
		}
		if( set->ruleSetPattern )
		{
			free(set->ruleSetPattern);
		}
	}
}


int loadRule(const char *filename)
{
#define LOAD_FAILED -1
#define LOAD_SUCCESS 0
	int ret = 0;
	FILE *f = NULL;
	char *buf= NULL;
	size_t bLen = 0;
	struct stat st;
	int totalLen = 0;

	int readLen = 0;
	int lineNum = 0;
	int i = 0;
	int idx = 0;

	if( !filename )
	{
		goto FAILED;
	}
	ret = access(filename, F_OK);
	if( ret < 0 )
	{
		printf("File %s doesn't exist!\n", filename);
		goto FAILED;
	}
	ret = stat(filename, &st);
	if( ret < 0 )
	{
		printf("Stat failed:%s\n", strerror(errno));
		goto FAILED;
	}
	totalLen = st.st_size;
	f = fopen(filename, "r");
	if( !f )
	{
		printf("Open file failed:%s\n", strerror(errno));
		goto FAILED;
	}

	while( (ret = getline( &buf, &bLen, f)) != -1 )
	{
		readLen += ret;
		lineNum++;
		if( lineNum%2 == 0 )
		{
			continue;
		}
		buf[ret-1] = '\0';
		idx = getTargetIdx(buf);
		if( idx < 0 )
		{
			printf("Unknow Target!\n");
			continue;
		}
		ruleCnt[idx]++;
	}

	if( readLen != totalLen )
	{
		printf("Read Error! readLen:%d totalLen:%d\n", readLen, totalLen);
		goto FAILED;
	}

	memset(ruleSetArray, 0x00, sizeof(ruleSetArray));
	for( ; i < TARGET_MAX; i++)
	{
		ruleSetArray[i].target = i;
		ruleSetArray[i].cnt = ruleCnt[i];
		ruleSetArray[i].r = (struct rule*)malloc(sizeof(struct rule)*ruleCnt[i]);
	}

	rewind(f);
	lineNum = 0;
	while( (ret = getline( &buf, &bLen, f)) != -1 )
	{
		lineNum++;
		if( lineNum%2 == 0 )
		{
			int cur = ruleSetArray[idx].cur;
			ruleSetArray[idx].r[cur].pattern = (char*)malloc(ret);
			ruleSetArray[idx].r[cur].len = ret-1;
			ruleSetArray[idx].r[cur].id = cur;
			memcpy(ruleSetArray[idx].r[cur].pattern, buf, ret-1);
			ruleSetArray[idx].r[cur].pattern[ret] = '\0';
			ruleSetArray[idx].cur++;
			ruleSetArray[idx].len += (ret-1);
			continue;
		}
		buf[ret-1] = '\0';
		idx = getTargetIdx(buf);
	}

	free(buf);

	return LOAD_SUCCESS;

FAILED:
	if( f )
	{
		fclose(f);
	}

	return LOAD_FAILED;
}

void dumpRule()
{
	int i = 0;
	int j = 0;
	int total = 0;

	if( !debug )
	{
		return;
	}

	for( ; i < TARGET_MAX; i++)
	{
		printf("Target:%s    Rule Cnt:%d\n", TargetName[i], ruleSetArray[i].cnt);
		for( j = 0; j < ruleSetArray[i].cnt; j++)
		{
			printf("[%d]-->Pattern:%s\n", ruleSetArray[i].r[j].id, ruleSetArray[i].r[j].pattern);
		}
		total += ruleSetArray[i].cnt;
		printf("------------------------------------------------------------\n\n");
	}
	printf("Total cnt:%d\n", total);
}

void buildRule()
{
	int i = 0;
	int j = 0;
	struct ruleSet *set = NULL;
	struct rule *r = NULL;
	hs_error_t ret = 0;
	hs_compile_error_t *err = NULL;

	for( ; i < TARGET_MAX; i++)
	{
		set = &ruleSetArray[i];
		/*Use '|' to concatenate each rule in this ruleSet, the final pattern enclosed by parenthesis ends with '\0'*/
		set->len = set->len + set->cnt - 1 + 2 + 1;
		for( j = 0; j < set->cnt; j++)
		{
			r = &(set->r[j]);
			r->e.re2Engine = new RE2(r->pattern, opt);

			ret = hs_compile(r->pattern, HS_FLAG_CASELESS|HS_FLAG_DOTALL|HS_FLAG_SINGLEMATCH|HS_FLAG_ALLOWEMPTY, HS_MODE_BLOCK, &platform, &r->e.hsEngine, &err);
			if( ret != HS_SUCCESS )
			{
				printf("Compile rule %s failed! Reason:%d:%s\n", r->pattern, err->expression, err->message);
				r->e.hsFailed= 1;
				continue;
			}
			ret = hs_alloc_scratch(r->e.hsEngine, &r->e.scratch);
			if( ret != HS_SUCCESS )
			{
				printf("Hyperscan alloc scratch failed! ret:%d\n", ret);
				r->e.hsFailed= 1;
				continue;
			}
		}
	}
	
	if( err )
	{
		hs_free_compile_error(err);
	}
}

void initGlobal()
{
	RE2::Options opt;
	hs_platform_info_t platform;

	/*128M=256<<19*/
	opt.set_max_mem(256<<25);
	opt.set_word_boundary(true);
	opt.set_perl_classes(true);
	opt.set_case_sensitive(false);
	opt.set_utf8(false);

	memset(&platform, 0x00, sizeof(platform));
	platform.cpu_features = HS_CPU_FEATURES_AVX2;
}

void dumpResult()
{
	int i = 0;
	int j = 0;
	struct ruleSet *set = NULL;
	struct rule *r = NULL;

	for( ; i < TARGET_MAX; i++)
	{
		set = &ruleSetArray[i];
		printf("------------------------------------------------------------\n");
		printf("|Target:%-20s   RuleCnt:%-2d                   |\n", TargetName[i], set->cnt);
		printf("------------------------------------------------------------\n");
		printf("|RuleId     |re2TimeConsumed(us)     |hsTimeConsumed(us)    |\n");
		for( j = 0; j < set->cnt; j++)
		{
			r = &(set->r[j]);
			printf("------------------------------------------------------------\n");
			printf("|RuleId:%-03d |re2Time:%-15.2f |hsTime:%-15.2f|\n", r->id, r->res.re2TimeConsumed, r->res.hsTimeConsumed);
		}
		printf("------------------------------------------------------------\n");
		printf("|RuleId:ALL |re2Time:%-15.2f |hsTime:%-15.2f|\n", set->res.re2TimeConsumed, set->res.hsTimeConsumed);
		printf("------------------------------------------------------------\n");
		printf("|RuleId:ALL |re2Time:%-15.2f |multiHsTime:%-10.2f|\n", set->multiRes.re2TimeConsumed, set->multiRes.hsTimeConsumed);
		printf("------------------------------------------------------------\n\n");

		printf("Match Rule:");
		for( j = 0; j < set->outcome.cur; j++)
		{
			printf("%02d ", set->outcome.id[j]);
		}
		printf("\n\n");
	}
}

void buildRuleSet()
{
	int i = 0;
	int j = 0;
	struct ruleSet *set = NULL;
	struct rule *r = NULL;
	hs_error_t ret = 0;
	hs_compile_error_t *err = NULL;
	int pos = 0;

	for( ; i < TARGET_MAX; i++)
	{
		pos = 0;
		j = 0;
		set = &ruleSetArray[i];
		set->ruleSetPattern = (char*)malloc(set->len);
		memset(set->ruleSetPattern, 0x00, set->len);

		set->ids = (unsigned int*)malloc(set->cnt*sizeof(unsigned int));
		set->flags = (unsigned int*)malloc(set->cnt*sizeof(unsigned int));
		set->multiPattern = (const char**)malloc(set->cnt*sizeof(char*));
		memset((void*)set->ids, 0x00, sizeof(int)*set->cnt);
		memset((void*)set->multiPattern, 0x00, sizeof(char*)*set->cnt);

		set->ruleSetPattern[pos++] = '(';
		do
		{
			r = &(set->r[j]);

			set->flags[j] = HS_FLAG_CASELESS|HS_FLAG_DOTALL|HS_FLAG_SINGLEMATCH|HS_FLAG_ALLOWEMPTY;
			set->ids[j] = r->id;
			set->multiPattern[j] = (char*)malloc((r->len+1)*sizeof(char));
			memcpy((void*)set->multiPattern[j], r->pattern, r->len);
			char *tmp = (char*)(set->multiPattern[j]);
			tmp[r->len] = '\0';

			if( pos + r->len + 2 > 16000 )
			{
				j++;
				continue;
			}
			if( j > 0 )
			{
				set->ruleSetPattern[pos++] = '|';
			}
			memcpy((void*)&(set->ruleSetPattern[pos]), (void*)r->pattern, r->len);
			pos += r->len;
			j++;
		}while( j < set->cnt);
		set->ruleSetPattern[pos] = ')';
		if( debug )
		{
			printf("ruleSet:%-24s ruleSetPatternLen:%-8d buf:%-8d\n", TargetName[i], pos+1, set->len);
		}

		set->e.re2Engine = new RE2(set->ruleSetPattern, opt);

		ret = hs_compile(set->ruleSetPattern, HS_FLAG_CASELESS|HS_FLAG_DOTALL|HS_FLAG_SINGLEMATCH|HS_FLAG_ALLOWEMPTY, HS_MODE_BLOCK, &platform, &set->e.hsEngine, &err);
		if( ret != HS_SUCCESS )
		{
			printf("Compile ruleSet %s failed! Reason:%d:%s\n", TargetName[i], err->expression, err->message);
			set->e.hsFailed= 1;
			continue;
		}
		ret = hs_alloc_scratch(set->e.hsEngine, &set->e.scratch);
		if( ret != HS_SUCCESS )
		{
			printf("Hyperscan alloc scratch failed! ret:%d\n", ret);
			set->e.hsFailed= 1;
			continue;
		}

		ret = hs_compile_multi(set->multiPattern, (const unsigned int*)set->flags, (const unsigned int*)set->ids, set->cnt, HS_MODE_BLOCK, &platform, &set->multiE.hsEngine, &err);
		if( ret != HS_SUCCESS )
		{
			printf("Compile ruleSet %s failed! Reason:%d:%s\n", TargetName[i], err->expression, err->message);
			set->multiE.hsFailed= 1;
			continue;
		}
		ret = hs_alloc_scratch(set->multiE.hsEngine, &set->multiE.scratch);
		if( ret != HS_SUCCESS )
		{
			printf("Hyperscan alloc scratch failed! ret:%d\n", ret);
			set->multiE.hsFailed= 1;
			continue;
		}
	}
}

int main(int argc, char *argv[])
{
	if( argc < 2 )
	{
		printf("Usage:%s RuleFileName [-g]\n", argv[0]);
		return 0;
	}

	if( argc == 3 )
	{
		if( strcmp(argv[2], "-g") == 0 )
		{
			debug = 1;
		}
	}

	initGlobal();

	loadRule(argv[1]);
	dumpRule();
	buildRule();
	buildRuleSet();

	test_re2();
	test_hyperscan();
	dumpResult();

	clean();

	return 0;
}



/*
 * tallow.c - IP block sshd login abuse
 *
 * (C) Copyright 2015-2019 Intel Corporation
 * Authors:
 *     Auke Kok <sofar@foo-projects.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include <pcre.h>
#include <systemd/sd-journal.h>

#include "json.h"
#include "data.h"

#define MAX_OFFSETS 30

static char ipt_path[PATH_MAX];
static char fwcmd_path[PATH_MAX];
static char nft_path[PATH_MAX];
static char backend_str[PATH_MAX];
static int expires = 3600;
static int has_ipv6 = 0;
static bool nocreate = false;
static bool conf_backend = false;
static bool exiting = false;
static sd_journal *j;

static int ext(char *fmt, ...)
{
	va_list args;
	char cmd[1024];
	int ret = 0;

	va_start(args, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, args);
	va_end(args);

	ret = system(cmd);
	if (ret)
		fprintf(stderr, "Error executing \"%s\": returned %d\n", cmd, ret);
	return (ret);
}

static void ext_ignore(char *fmt, ...)
{
	va_list args;
	char cmd[1024];

	va_start(args, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, args);
	va_end(args);

	__attribute__((unused)) int ret = system(cmd);
}

struct backend_struct {
	char name[32];
	bool is_setup;
	int(*probe)(void);
	int(*setup)(void);
	int(*teardown)(void);
	int(*block)(char *addr, int timeout);
	int(*block6)(char *addr, int timeout);
};

/*
 * ipset common functions - for fwcmd and iptables backends
 */

static int ipset_block(char *addr, int timeout)
{
	if (timeout > 0) {
		return ext("%s/ipset -! add tallow %s timeout %d",
			   ipt_path, addr, timeout);
	} else {
		return ext("%s/ipset -! add tallow %s", ipt_path, addr);
	}
}

static int ipset_block6(char *addr, int timeout)
{
	if (timeout > 0) {
		return ext("%s/ipset -! add tallow6 %s timeout %d",
			   ipt_path, addr, timeout);
	} else {
		return ext("%s/ipset -! add tallow6 %s", ipt_path, addr);
	}
}

/*
 * firewall-cmd
 */
static int fwcmd_probe(void)
{
	if ((access(fwcmd_path, X_OK) == 0) && ext("%s/firewall-cmd --state --quiet", fwcmd_path) == 0)
		return 0;

	return 1;
}

static int fwcmd_setup(void)
{
	/* create ipv4 rule and ipset */
	if (ext("%s/firewall-cmd --permanent --quiet --new-ipset=tallow --type=hash:ip --family=inet --option=timeout=%d", fwcmd_path, expires)) {
		fprintf(stderr, "Unable to create ipv4 ipset with firewall-cmd.\n");
		exit(EXIT_FAILURE);
	}
	if (ext("%s/firewall-cmd --permanent --direct --quiet --add-rule ipv4 filter INPUT 1 -m set --match-set tallow src -j DROP", fwcmd_path)) {
		fprintf(stderr, "Unable to create ipv4 firewalld rule.\n");
		exit(EXIT_FAILURE);
	}

	/* create ipv6 rule and ipset */
	if (has_ipv6) {
		if (ext("%s/firewall-cmd --permanent --quiet --new-ipset=tallow6 --type=hash:ip --family=inet6 --option=timeout=%d", fwcmd_path, expires)) {
			fprintf(stderr, "Unable to create ipv6 ipset with firewall-cmd.\n");
			exit(EXIT_FAILURE);
		}
		if (ext("%s/firewall-cmd --permanent --direct --quiet --add-rule ipv6 filter INPUT 1 -m set --match-set tallow6 src -j DROP ", fwcmd_path)) {
			fprintf(stderr, "Unable to create ipv6 firewalld rule.\n");
			exit(EXIT_FAILURE);
		}
	}

	/* reload firewalld for ipsets to load */
	if (ext("%s/firewall-cmd --reload --quiet", fwcmd_path, expires)) {
		fprintf(stderr, "Unable to reload firewalld rules.\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}

static int fwcmd_teardown(void)
{
	/* reset all rules in case the running fw changes */
	ext_ignore("%s/firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 1 -m set --match-set tallow src -j DROP 2> /dev/null", fwcmd_path);
	ext_ignore("%s/firewall-cmd --permanent --delete-ipset=tallow 2> /dev/null", fwcmd_path);

	if (has_ipv6) {
		ext_ignore("%s/firewall-cmd --permanent --direct --remove-rule ipv6 filter INPUT 1 -m set --match-set tallow6 src -j DROP 2> /dev/null", fwcmd_path);
		ext_ignore("%s/firewall-cmd --permanent --delete-ipset=tallow6 2> /dev/null", fwcmd_path);
	}
	return 0;
}

/*
 * nft
 */
static int nft_probe(void)
{
	if ((access(nft_path, X_OK) == 0) && ((ext("%s/nft list tables > /dev/null", nft_path) == 0)))
		return 0;
	return 1;
}

static int nft_setup(void)
{
	int ret;

	/* we could pipe all of this in a single command */
	ret =
	ext("%s/nft add table inet tallow_table { chain tallow_chain { type filter hook input priority filter\\; policy accept\\; }\\; }", nft_path) ?:
	ext("%s/nft add set inet tallow_table tallow_set { type ipv4_addr\\; timeout %ds \\;}", nft_path, expires) ?:
	ext("%s/nft add rule inet tallow_table tallow_chain ip saddr @tallow_set drop", nft_path);
	if (ret == 0 && has_ipv6 ) {
		ret = ext("%s/nft add set inet tallow_table tallow6_set { type ipv6_addr\\; timeout %ds \\;}", nft_path, expires) ?:
		ext("%s/nft add rule inet tallow_table tallow_chain ip6 saddr @tallow6_set drop", nft_path);
	}
	return ret;
}

static int nft_teardown(void)
{
	/* teardown is super easy with nft */
	return ext("%s/nft delete table inet tallow_table", nft_path);
}

static int nft_block(char *addr, int timeout)
{
	if (timeout > 0)
		return ext("%s/nft add element inet tallow_table tallow_set { %s timeout %ds }", nft_path, addr, timeout);

	return ext("%s/nft add element inet tallow_table tallow_set { %s }", nft_path, addr);
}

static int nft_block6(char *addr, int timeout)
{
	if (timeout > 0)
		return ext("%s/nft add element inet tallow_table tallow6_set { %s timeout %ds }", nft_path, addr, timeout);

	return ext("%s/nft add element inet tallow_table tallow6_set { %s }", nft_path, addr);
}

/*
 * iptables
 */
static int iptables_probe(void)
{
	/* no-op, will always fall back to iptables no matter what */
	return 0;
}

static int iptables_setup(void)
{
	/* create ipv4 rule and ipset */
	if (ext("%s/ipset create tallow hash:ip family inet timeout %d", ipt_path, expires)) {
		fprintf(stderr, "Unable to create ipv4 ipset.\n");
		exit(EXIT_FAILURE);
	}
	if (ext("%s/iptables -t filter -I INPUT 1 -m set --match-set tallow src -j DROP", ipt_path)) {
		fprintf(stderr, "Unable to create iptables rule.\n");
		exit(EXIT_FAILURE);
	}

	/* create ipv6 rule and ipset */
	if (has_ipv6) {
		if (ext("%s/ipset create tallow6 hash:ip family inet6 timeout %d", ipt_path, expires)) {
			fprintf(stderr, "Unable to create ipv6 ipset.\n");
			exit(EXIT_FAILURE);
		}
		if (ext("%s/ip6tables -t filter -I INPUT 1 -m set --match-set tallow6 src -j DROP", ipt_path)) {
			fprintf(stderr, "Unable to create ipt6ables rule.\n");
			exit(EXIT_FAILURE);
		}
	}

	return 0;
}

static int iptables_teardown(void)
{
	ext_ignore("%s/iptables -t filter -D INPUT -m set --match-set tallow src -j DROP 2> /dev/null", ipt_path);
	ext_ignore("%s/ipset destroy tallow 2> /dev/null", ipt_path);

	if (has_ipv6) {
		ext_ignore("%s/ip6tables -t filter -D INPUT -m set --match-set tallow6 src -j DROP 2> /dev/null", ipt_path);
		ext_ignore("%s/ipset destroy tallow6 2> /dev/null", ipt_path);
	}

	return 0;
}

#define MAX_BACKENDS 3
static struct backend_struct backends[MAX_BACKENDS] = {
	{ .name = "nft",          .probe = nft_probe,      .setup = nft_setup,      .teardown = nft_teardown,      .block = nft_block,   .block6 = nft_block6 },
	{ .name = "firewall-cmd", .probe = fwcmd_probe,    .setup = fwcmd_setup,    .teardown = fwcmd_teardown,    .block = ipset_block, .block6 = ipset_block6 },
	{ .name = "iptables",     .probe = iptables_probe, .setup = iptables_setup, .teardown = iptables_teardown, .block = ipset_block, .block6 = ipset_block6 },
};
static struct backend_struct *backend = NULL;


static void setup(void)
{
	/* pick backend */
	if (conf_backend) {
		for (int b = 0; b < MAX_BACKENDS; b++) {
			if (strcmp(backends[b].name, backend_str) == 0) {
				fprintf(stderr, "Using backend from config: %s\n", backends[b].name);
				backend = &backends[b];
				backend->is_setup = false;
				break;
			}
		}
	} else {
		/* probe backends */
		for (int b = 0; b < MAX_BACKENDS; b++) {
			if (backends[b].probe() == 0) {
				fprintf(stderr, "Using backend: %s\n", backends[b].name);
				backend = &backends[b];
				backend->is_setup = false;
				break;
			}
		}
	}

	if (backend == NULL) {
		fprintf(stderr, "All backends failed to probe, cannot continue!\n");
		exit(EXIT_FAILURE);
	}

	if (nocreate)
		return;

	if (backend->setup()) {
		fprintf(stderr, "Backend \"%s\" failed to setup, cannot continue!\n", backend->name);
		exit(EXIT_FAILURE);
	}
	backend->is_setup = true;
}

static void block(struct block_struct *s, int instant_block)
{
	int failed = 0;
	int ret;

again:
	if (strchr(s->ip, ':')) {
		if (!has_ipv6)
			return;

		ret = backend->block6(s->ip, instant_block);
	} else {
		ret = backend->block(s->ip, instant_block);
	}

	if (ret) {
		/* blocking failed. We will try a few times to teardown()->setup()->block() */
		failed++;
		if (failed > 3) {
			fprintf(stderr, "Backend \"%s\" permanently failed, cannot continue!\n", backend->name);
			exit(EXIT_FAILURE);
		}

		fprintf(stderr, "Backend \"%s\" failed, trying to re-initialize\n", backend->name);

		if (backend->teardown()) {
			fprintf(stderr, "Backend \"%s\" failed to teardown, cannot continue!\n", backend->name);
			exit(EXIT_FAILURE);
		}
		backend->is_setup = false;

		sleep(1);

		if (backend->setup()) {
			fprintf(stderr, "Backend \"%s\" failed to setup, cannot continue!\n", backend->name);
			exit(EXIT_FAILURE);
		}
		backend->is_setup = true;
		goto again;
	}

	if (instant_block > 0) {
		dbg("Throttled %s\n", s->ip);
	} else {
		fprintf(stderr, "Blocked %s\n", s->ip);
		s->blocked = true;
	}
}

static void find(const char *ip, float weight, int instant_block)
{
	struct block_struct *s = blocks;
	struct block_struct *n;

	if (!ip)
		return;

	/*
	 * not validating the IP address format here, just
	 * making sure we're not passing special characters
	 * to system().
	 */
	if (strspn(ip, "0123456789abcdef:.") != strlen(ip))
		return;

	if (whitelist_find(ip))
		return;

	/* walk and update entry */
	while (s) {
		if (!strcmp(s->ip, ip)) {
			s->score += weight;
			dbg("%s: %1.3f\n", s->ip, s->score);
			(void) gettimeofday(&s->time, NULL);

			if (s->blocked) {
				return;
			}

			if (s->score >= 1.0) {
				block(s, 0);
			} else if (instant_block > 0) {
				block(s, instant_block);
			}

			return;
		}

		if (s->next)
			s = s->next;
		else
			break;
	}

	/* append */
	n = calloc(1, sizeof(struct block_struct));
	if (!n) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	if (!blocks)
		blocks = n;
	else
		s->next = n;

	n->ip = strdup(ip);
	n->score = weight;
	n->next = NULL;
	n->blocked = false;
	(void) gettimeofday(&n->time, NULL);
	dbg("%s: %1.3f\n", n->ip, n->score);

	if (weight >= 1.0) {
		block(n, 0);
	} else if (instant_block > 0) {
		block(n, instant_block);
	}
	return;
}

#ifdef DEBUG
static void sigusr1(int u __attribute__ ((unused)))
{
	fprintf(stderr, "Dumping score list on request:\n");
	struct block_struct *s = blocks;
	while (s) {
		fprintf(stderr, "%ld %s %1.3f\n", s->time.tv_sec, s->ip, s->score);
		s = s->next;
	}
}
#endif

static void sigint(int u __attribute__ ((unused)))
{
	exiting = true;
}


int main(void)
{
	int r;
	FILE *f;
	int timeout = 5; // how long a ^C or TERM may wait...
	long long unsigned int last_timestamp = 0;
	struct sigaction s_int;

	json_load_patterns();

	strcpy(ipt_path, "/usr/sbin");
	strcpy(fwcmd_path, "/usr/sbin");
	strcpy(nft_path, "/usr/sbin");

	/* ^C and TERM handler */
	memset(&s_int, 0, sizeof(struct sigaction));
	s_int.sa_handler = sigint;
	sigaction(SIGINT, &s_int, NULL);
	sigaction(SIGTERM, &s_int, NULL);

#ifdef DEBUG
	fprintf(stderr, "Debug output enabled. Send SIGUSR1 to dump internal state table\n");

	struct sigaction s_usr1;

	memset(&s_usr1, 0, sizeof(struct sigaction));
	s_usr1.sa_handler = sigusr1;
	sigaction(SIGUSR1, &s_usr1, NULL);
#endif

	if (access("/proc/sys/net/ipv6", R_OK | X_OK) == 0)
		has_ipv6 = 1;

	f = fopen(SYSCONFDIR "/tallow.conf", "r");
	if (f) {
		char buf[256];
		char *key;
		char *val;

		while (fgets(buf, 80, f) != NULL) {
			char *c;

			c = strchr(buf, '\n');
			if (c) *c = 0; /* remove trailing \n */

			if (buf[0] == '#')
				continue; /* comment line */

			key = strtok(buf, "=");
			if (!key)
				continue;
			val = strtok(NULL, "=");
			if (!val)
				continue;

			// todo: filter leading/trailing whitespace
			if (!strcmp(key, "ipt_path"))
				strncpy(ipt_path, val, PATH_MAX - 1);
			if (!strcmp(key, "fwcmd_path"))
				strncpy(fwcmd_path, val, PATH_MAX - 1);
			if (!strcmp(key, "nft_path"))
				strncpy(nft_path, val, PATH_MAX - 1);
			if (!strcmp(key, "backend")) {
				conf_backend = true;
				strncpy(backend_str, val, PATH_MAX -1);
			}
			if (!strcmp(key, "expires"))
				expires = atoi(val);
			if (!strcmp(key, "whitelist"))
				whitelist_add(val);
			if (!strcmp(key, "ipv6"))
				has_ipv6 = atoi(val);
			if (!strcmp(key, "nocreate"))
				nocreate = (atoi(val) == 1);
		}
		fclose(f);
	}

	if (!has_ipv6)
		fprintf(stderr, "ipv6 support disabled.\n");

	if (!whitelist) {
		whitelist_add("127.0.0.1");
		whitelist_add("192.168.");
		whitelist_add("10.");
	}

	r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
	if (r < 0) {
		fprintf(stderr, "Failed to open journal: %s\n", strerror(-r));
		exit(EXIT_FAILURE);
	}

	/* add all filters */
	struct filter_struct *flt = filters;
	while (flt) {
		sd_journal_add_match(j, flt->filter, 0);
		dbg("Subbed %s\n", flt->filter);
		flt = flt->next;
	}

	/* go to the tail and wait */
	r = sd_journal_seek_tail(j);
	sd_journal_previous(j);
	sd_journal_wait(j, (uint64_t) 0);
	dbg("sd_journal_seek_tail() returned %d\n", r);
	while (sd_journal_next(j) != 0)
		r++;
	dbg("Forwarded through %d items in the journal to reach the end\n", r);

	setup();

	fprintf(stderr, "Started v" PACKAGE_VERSION "\n");

	for (;;) {
		const void *d, *dt;
		size_t l, dl;

		r = sd_journal_wait(j, (uint64_t) timeout * 1000000);

		if (exiting) {
			if ((backend != NULL) && backend->is_setup)
				backend->teardown();
			break;
		}

		if (r == SD_JOURNAL_INVALIDATE) {
			fprintf(stderr, "Journal was rotated, resetting\n");
			sd_journal_seek_tail(j);
			sd_journal_previous(j);
		} else if (r == SD_JOURNAL_NOP) {
			dbg("Timeout reached, waiting again\n");
			continue;
		}

		while (sd_journal_next(j) != 0) {
			char *m;

			/*
			 * discard messages older than ones we've already seen before
			 * this happens when the journal rotates - we get replayed events
			 */
			if (sd_journal_get_data(j, "_SOURCE_REALTIME_TIMESTAMP", &dt, &dl) == 0) {
				long long unsigned int lt = atoll(dt + strlen("_SOURCE_REALTIME_TIMESTAMP="));
				if (lt > last_timestamp)
					last_timestamp = lt;
				else if (lt < last_timestamp) {
					dbg("Discarding old entry: %llu - %llu\n", lt, last_timestamp);
					continue;
				}
			}

			if (sd_journal_get_data(j, "MESSAGE", &d, &l) < 0) {
				fprintf(stderr, "Failed to read message field: %s\n", strerror(-r));
				break;
			}

			m = strndup(d, l+1);
			m[l] = '\0';

			dbg("msg %s\n", m);

			struct pattern_struct *pat = patterns;
			while (pat) {
				int off[MAX_OFFSETS];
				int ret = pcre_exec(pat->re, NULL, m, l, 0, 0, off, MAX_OFFSETS);
				if (ret == 2) {
					const char *s;
					ret = pcre_get_substring(m, off, 2, 1, &s);
					if (ret > 0) {
						dbg("%s == %s (%d!)\n", s, pat->pattern, pat->instant_block);
						find(s, pat->weight, pat->instant_block);
						pcre_free_substring(s);
					}
				}

				pat = pat->next;
			}

			free(m);

		}

		prune(expires);
	}

	sd_journal_close(j);

	exit(EXIT_SUCCESS);
}

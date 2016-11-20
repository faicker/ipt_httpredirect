#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <linux/version.h>
#include "xt_HTTPREDIRECT.h"

enum {
    HTTPREDIRECT_URL = 1 << 0,
};

static const struct option HTTPREDIRECT_opts[] = {
	{ .name = "httpredirect-url", .has_arg = 1, .flag = NULL, .val = HTTPREDIRECT_URL},
	{ .name = NULL }
};

static void HTTPREDIRECT_help(void)
{
	printf(
"HTTPREDIRECT target options:\n"
"--httpredirect-url url              http redirect to url\n");
}

static void HTTPREDIRECT_init(struct xt_entry_target *t)
{
    return;
}

static int HTTPREDIRECT_parse(int c, char **argv, int invert, unsigned int *flags,
        const void *entry, struct xt_entry_target **target)
{
    struct xt_httpredirect_info *info = (struct xt_httpredirect_info *)(*target)->data;
    size_t length;
    switch (c) {
        case HTTPREDIRECT_URL:
            if (*flags & HTTPREDIRECT_URL)
                xtables_error(PARAMETER_PROBLEM,
                        "Can't specify --httpredirect-url twice");
            if (xtables_check_inverse(optarg, &invert, NULL, 0, argv))
                xtables_error(PARAMETER_PROBLEM,
                        "Unexpected `!' after --httpredirect-url");
            length = strlen(optarg);
            if (length == 0)
                xtables_error(PARAMETER_PROBLEM,
                        "No url specified for --httpredirect-url");
            if (length >= sizeof(info->url))
                xtables_error(PARAMETER_PROBLEM,
                        "--httpredirect-url too long, max %Zu characters",
                        sizeof(info->url) - 1);
            strcpy(info->url, optarg);
            break;
        default:
            return 0;
    }
    *flags |= c;
    return 1;
}

static void HTTPREDIRECT_print(const void *ip, const struct xt_entry_target *target,
        int numeric)
{
    struct xt_httpredirect_info *info = (struct xt_httpredirect_info *)target->data;
    if (info->url[0] != '\0') {
        printf("httpredirect-url ");
        xtables_save_string(info->url);
    }
}

static void HTTPREDIRECT_save(const void *ip, const struct xt_entry_target *target)
{
    struct xt_httpredirect_info *info = (struct xt_httpredirect_info *)target->data;
    if (info->url[0] != '\0') {
        printf("--httpredirect-url ");
        xtables_save_string(info->url);
    }
}

static struct xtables_target httpredirect_tg_reg = {
    .name    = "HTTPREDIRECT",
    .version  = XTABLES_VERSION,
    .family    = NFPROTO_IPV4,
    .size    = XT_ALIGN(sizeof(struct xt_httpredirect_info)),
    .userspacesize  = XT_ALIGN(sizeof(struct xt_httpredirect_info)),
    .help    = HTTPREDIRECT_help,
    .init    = HTTPREDIRECT_init,
    .parse    = HTTPREDIRECT_parse,
    .print    = HTTPREDIRECT_print,
    .save    = HTTPREDIRECT_save,
    .extra_opts  = HTTPREDIRECT_opts,
};

void _init(void)
{
    xtables_register_target(&httpredirect_tg_reg);
}

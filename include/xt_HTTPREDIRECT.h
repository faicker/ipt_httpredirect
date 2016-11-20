#ifndef _XT_HTTP_REDIRECT_H
#define _XT_HTTP_REDIRECT_H
#include <linux/types.h>

#define STR_MAX 63
struct xt_httpredirect_info {
    char url[STR_MAX + 1];
};
#endif

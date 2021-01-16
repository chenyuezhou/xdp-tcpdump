
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#include <config.h>


void _print_options(const option_wrapper_t *long_option_wrapper, int option_type)
{
    int  i, pos;
    char buf[BUFSIZ];

    for (i = 0; long_option_wrapper[i].option.name != 0; i++) {
        if (long_option_wrapper[i].type != option_type) {
            continue;
        }

        if (long_option_wrapper[i].option.val > 64) {
            printf(" -%c,", long_option_wrapper[i].option.val);
        } else {
            printf("    ");
        }

        pos = snprintf(buf, BUFSIZE, " --%s", long_option_wrapper[i].option.name);
        if (long_option_wrapper[i].metavar) {
            snprintf(buf + pos, BUFSIZE - pos, " %s",
                     long_option_wrapper[i].metavar);
        }

        printf("%-28s", buf);
        printf("  %s\n", long_option_wrapper[i].help);
    }
}


static void _usage(const char *prog_name,
                   const option_wrapper_t *long_option_wrapper, const char *doc)
{
    printf("Usage: %s [options]\n\n", prog_name);

    printf("DOCUMENTATION:\n %s\n", doc);
    printf("Required options:\n");
    _print_options(long_option_wrapper, OPT_REQURIED);
    printf("\n");
    printf("Optional options:\n");
    _print_options(long_option_wrapper, OPT_OPTIONAL);
    printf("\n");
    printf("Other options:\n");
    _print_options(long_option_wrapper, OPT_OTHER);
}


static struct option *option_wrapper2option(
        const option_wrapper_t *long_option_wrapper)
{
    int i, num = 0;
    struct option *long_option;

    for (i = 0; long_option_wrapper[i].option.name != 0; i++) {
        num++;
    }

    long_option = malloc(sizeof(struct option) * num);
    for (i = 0; i < num; i++) {
        memcpy(&long_option[i], &long_option_wrapper[i], sizeof(struct option));
    }

    return long_option;
}


static void addr_to_net_byte(const char *optarg, struct in_addr *addr) {
    if (inet_aton(optarg, addr) == 0) {
        fprintf(stderr, "Invalid address\n");

        exit(0);
    }
}


void parse_params_to_xdp_config(int argc, char * const *argv, xdp_config_t *config,
                                const option_wrapper_t *long_option_wrapper,
                                const char *doc)
{
    int            c, option_index = 0;
    struct in_addr addr;
    struct option *long_option = option_wrapper2option(long_option_wrapper);

    /* init xdp_config_t */
    config->count           = -1;
    config->print_timestamp = false;
    config->ifindex         = -1;
    config->filename        = NULL;
    config->xdp_flags       = XDP_FLAGS_SKB_MODE;
    config->obj             = NULL;
    config->rule            = calloc(1, sizeof(custom_rule_t));

    while ((c = getopt_long(argc, argv, "c:vi:htAH", long_option, &option_index))
            != -1)
    {
        switch (c) {
            case 'c':
                config->count = atoi(optarg);

                break;

            case 'i':
                config->ifname  = strdup(optarg);
                config->ifindex = if_nametoindex(config->ifname);

                break;

            case 't':
                config->print_timestamp = true;

                break;

            case 'A':
                config->ifindex = -1;

                break;

            case 'H':
                config->xdp_flags =
                    XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_HW_MODE;

                break;

            case 'S':
                config->xdp_flags =
                    XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;

                break;

            case 1:
                /* specifies ebpf-elf file */
                config->filename = strdup(optarg);

                break;

            case 2:
                config->rule->protocol = IPPROTO_TCP;

                break;

            case 3:
                config->rule->protocol = IPPROTO_UDP;

                break;

            case 4:
                config->rule->port = htons(atoi(optarg));

                break;

            case 5:
                config->rule->dest = htons(atoi(optarg));

                break;

            case 6:
                config->rule->source = htons(atoi(optarg));

                break;

            case 7:
                addr_to_net_byte(optarg, &addr);
                config->rule->addr = addr.s_addr;

                break;

            case 8:
                addr_to_net_byte(optarg, &addr);
                config->rule->daddr = addr.s_addr;

                break;

            case 9:
                addr_to_net_byte(optarg, &addr);
                config->rule->saddr = addr.s_addr;

                break;

            case 'v':
#ifdef VERSION
                printf("Version: %s\n", VERSION);
#else
                printf("Version: unkown\n");
#endif

                goto done;

            case 'h':
                _usage(argv[0], long_option_wrapper, doc);

            default:
done:
                free(long_option);
                exit(0);
        }

        option_index = 0;
    }

    (void) option_index;

    free(long_option);
}

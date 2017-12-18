/*
 * Copyright (C) 2017 Andrea Zagli <azagli@libero.it>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "apr_strings.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"

#ifdef HAVE_CONFIG_H
	#include <config.h>
#endif

#include <libzakautho/libzakautho.h>

static void register_hooks (apr_pool_t *pool);
static void *create_authn_zakauthe_dir_config (apr_pool_t *p, char *d);
static const char *set_option (cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2);

/* Per-directory configuration */
typedef struct {
	char *plugin_name;
	GSList *sl_options;
} zakauthe_config;

static const command_rec authn_zakauthe_cmds[] =
{
	AP_INIT_TAKE1 ("AuthZakAuthePlugin",
	               ap_set_string_slot,
	               (void *)APR_OFFSETOF (zakauthe_config, plugin_name),
	               OR_AUTHCFG,
	               "Plugin with full path"),
	AP_INIT_TAKE2 ("AuthZakAutheOption",
	               set_option,
	               NULL,
	               OR_AUTHCFG,
	               "An option with the value"),
	{NULL}
};

module AP_DECLARE_DATA authn_zakauthe_module =
{
	STANDARD20_MODULE_STUFF,
	create_authn_zakauthe_dir_config,    /* dir config creater */
	NULL,                            /* dir merger --- default is to override */
	NULL,                            /* server config */
	NULL,                            /* merge server config */
	authn_zakauthe_cmds,                 /* command apr_table_t */
	register_hooks                   /* register hooks */
};

static authn_status
check_password (request_rec *r,
                const char *user,
                const char *password)
{
	authn_status ret;

	ZakAuthe *authe;
	GSList *sl_authe_params;
	GSList *sl_loop;

	zakauthe_config *config = (zakauthe_config *)ap_get_module_config (r->per_dir_config, &authn_zakauthe_module);

	sl_authe_params = NULL;
	sl_authe_params = g_slist_append (sl_authe_params, g_strdup (config->plugin_name));

	sl_loop = g_slist_nth (config->sl_options, 0);
	while (sl_loop != NULL)
		{
			sl_authe_params = g_slist_append (sl_authe_params, g_strdup ((const gchar *)sl_loop->data));

			sl_loop = g_slist_next (sl_loop);
		}

	authe = zak_authe_new ();

	if (zak_authe_set_config (authe, sl_authe_params))
		{
			if (zak_authe_authe_nogui (authe, user, password, NULL))
				{
					ret = AUTH_GRANTED;
				}
			else
				{
					ret = AUTH_DENIED;
				}
		}
	else
		{
			ret = AUTH_DENIED;
		}

	g_object_unref (authe);
	g_slist_free_full (sl_authe_params, g_free);

	return ret;
}

static authn_status
get_realm_hash (request_rec *r,
                const char *user,
                const char *realm,
                char **rethash)
{
	return AUTH_GRANTED;
}

static const authn_provider authn_zakauthe_provider =
	{
		&check_password,
		&get_realm_hash,
	};

static void
register_hooks (apr_pool_t *pool)
{
	ap_register_auth_provider (pool, AUTHN_PROVIDER_GROUP, "zakauthe",
	                           AUTHN_PROVIDER_VERSION,
	                           &authn_zakauthe_provider, AP_AUTH_INTERNAL_PER_CONF);
}

/*
 * Constructor for per-directory configuration
 */
static void *
create_authn_zakauthe_dir_config (apr_pool_t *p, char *d)
{
	zakauthe_config *conf = apr_pcalloc (p, sizeof (zakauthe_config));

	conf->plugin_name = NULL;
	conf->sl_options = NULL;

	return conf;
}

static const char
*set_option (cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2)
{
	zakauthe_config *conf = (zakauthe_config *)cfg;

	conf->sl_options = g_slist_append (conf->sl_options, (gpointer)g_strdup (arg2));

	return NULL;
}

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

#include <libzakautho/autho.h>

static void register_hooks (apr_pool_t *pool);
static void *create_authz_zakautho_dir_config (apr_pool_t *p, char *d);

/* Per-directory configuration */
typedef struct {
	char *xml_filename;
	char *db_cnc_string;
	char *db_table_name_prefix;
	char *role_name_prefix;
	char *resource_name_prefix;
	char *user_decoration;
} zakautho_config;

static const command_rec authz_zakautho_cmds[] =
{
	AP_INIT_TAKE1 ("AuthZakAuthoXmlFilename",
	               ap_set_string_slot,
	               (void *)APR_OFFSETOF (zakautho_config, xml_filename),
	               OR_AUTHCFG,
	               "Full path of xml file from which load config"),
	AP_INIT_TAKE1 ("AuthZakAuthoDbCncString",
	               ap_set_string_slot,
	               (void *)APR_OFFSETOF (zakautho_config, db_cnc_string),
	               OR_AUTHCFG,
	               "Connection string for database from which load config"),
	AP_INIT_TAKE1 ("AuthZakAuthoDbTableNamePrefix",
	               ap_set_string_slot,
	               (void *)APR_OFFSETOF (zakautho_config, db_table_name_prefix),
	               OR_AUTHCFG,
	               "Table name prefix to use for database from which load config"),
	AP_INIT_TAKE1 ("AuthZakAuthoRoleNamePrefix",
	               ap_set_string_slot,
	               (void *)APR_OFFSETOF (zakautho_config, role_name_prefix),
	               OR_AUTHCFG,
	               "Role name prefix"),
	AP_INIT_TAKE1 ("AuthZakAuthoResourceNamePrefix",
	               ap_set_string_slot,
	               (void *)APR_OFFSETOF (zakautho_config, resource_name_prefix),
	               OR_AUTHCFG,
	               "Resource name prefix"),
	AP_INIT_TAKE1 ("AuthZakAuthoUserDecoration",
	               ap_set_string_slot,
	               (void *)APR_OFFSETOF (zakautho_config, user_decoration),
	               OR_AUTHCFG,
	               "A string to convert the user name; the %s is replaced with the username"),
	{NULL}
};

module AP_DECLARE_DATA authz_zakautho_module =
{
	STANDARD20_MODULE_STUFF,
	create_authz_zakautho_dir_config,    /* dir config creater */
	NULL,                            /* dir merger --- default is to override */
	NULL,                            /* server config */
	NULL,                            /* merge server config */
	authz_zakautho_cmds,                 /* command apr_table_t */
	register_hooks                   /* register hooks */
};

static authz_status
check_authorization (request_rec *r,
                     const char *require_args,
                     const void *parsed_require_args)
{
	const char *err = NULL;
	const ap_expr_info_t *expr = parsed_require_args;
	const char *require;

	const char *t;
	const char *w;

	char *_user;

	ZakAutho *autho;
	ZakAuthoIRole *role_user;

	zakautho_config *config;

	if (!r->user)
		{
			return AUTHZ_DENIED_NO_USER;
		}

	require = ap_expr_str_exec (r, expr, &err);
	if (err)
		{
			ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02594)
			               "authz_zakautho authorize: require user: Can't "
			               "evaluate require expression: %s", err);
			return AUTHZ_DENIED;
		}

	config = (zakautho_config *)ap_get_module_config (r->per_dir_config, &authz_zakautho_module);

	autho = zak_autho_new ();
	if (autho == NULL)
		{
			ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02594)
			               "Unable to create the libzakautho object.");
			return AUTHZ_DENIED;
		}

	if (config->xml_filename != NULL)
		{
			xmlDocPtr xdoc;
			xmlNodePtr xnode;

			xdoc = xmlParseFile (config->xml_filename);
			if (xdoc != NULL)
				{
					ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02594)
					               "Unable to parse the libzakautho configuration from xml file «%s».",
					               config->xml_filename);
					return AUTHZ_DENIED;
				}

			xnode = xmlDocGetRootElement (xdoc);
			if (!zak_autho_load_from_xml (autho, xnode, TRUE))
				{
					ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02594)
					               "Unable to load the libzakautho configuration from xml file «%s».",
					               config->xml_filename);
					return AUTHZ_DENIED;
				}
		}
	else if (config->db_cnc_string != NULL)
		{
			GError *error;
			GdaConnection *gdacon;

			error = NULL;
			gdacon = gda_connection_open_from_string (NULL, config->db_cnc_string, NULL, 0, &error);
			if (gdacon == NULL || error != NULL)
				{
					ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02594)
					               "Unable to create connection to db: %s.",
					               error != NULL && error->message != NULL ? error->message : "no details");
					return AUTHZ_DENIED;
				}

			if (!zak_autho_load_from_db_with_monitor (autho, gdacon,
			                                          config->db_table_name_prefix != NULL ? config->db_table_name_prefix : NULL,
			                                          TRUE))
				{
					ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02594)
					               "Unable to load the libzakautho configuration from db.");
					return AUTHZ_DENIED;
				}
		}

	_user = g_strdup_printf (config->user_decoration != NULL ? config->user_decoration : "%s", r->user);
	role_user = zak_autho_get_role_from_id (autho, _user);
	if (role_user == NULL)
		{
			ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02594)
			               "User «%s» not found on libzakautho configuration.", _user);
			return AUTHZ_DENIED;
		}
	g_free (_user);

	if (config->role_name_prefix != NULL)
		{
			zak_autho_set_role_name_prefix (autho, config->role_name_prefix);
		}
	if (config->resource_name_prefix != NULL)
		{
			zak_autho_set_resource_name_prefix (autho, config->resource_name_prefix);
		}

	t = require;
	while ((w = ap_getword_conf (r->pool, &t)) && w[0])
		{
			ZakAuthoIResource *resource;

			resource = zak_autho_get_resource_from_id (autho, w);
			if (resource == NULL)
				{
					ap_log_rerror (APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(02594)
					               "Resource «%s» not found on libzakautho configuration.", w);
				}
			else
				{
					if (zak_autho_is_allowed (autho, role_user, resource, FALSE))
						{
							return AUTHZ_GRANTED;
						}
				}
		}

	ap_log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01663)
	               "access to %s failed, reason: user '%s' does not meet "
	               "'require'ments for user to be allowed access",
	               r->uri, r->user);

	return AUTHZ_DENIED;
}

static const char
*parse_config (cmd_parms *cmd, const char *require_line,
               const void **parsed_require_line)
{
	const char *expr_err = NULL;
	ap_expr_info_t *expr;

	expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT,
	                         &expr_err, NULL);

	if (expr_err)
		return apr_pstrcat(cmd->temp_pool,
		                   "Cannot parse expression in require line: ",
		                   expr_err, NULL);

	*parsed_require_line = expr;

	return NULL;
}

static const authz_provider authz_zakautho_provider =
	{
		&check_authorization,
		&parse_config,
	};

static void
register_hooks (apr_pool_t *pool)
{
	ap_register_auth_provider (pool, AUTHZ_PROVIDER_GROUP, "zakautho",
	                           AUTHZ_PROVIDER_VERSION,
	                           &authz_zakautho_provider, AP_AUTH_INTERNAL_PER_CONF);
}

/*
 * Constructor for per-directory configuration
 */
static void *
create_authz_zakautho_dir_config (apr_pool_t *p, char *d)
{
	zakautho_config *conf = apr_pcalloc (p, sizeof (zakautho_config));

	conf->xml_filename = NULL;
	conf->db_cnc_string = NULL;
	conf->db_table_name_prefix = NULL;
	conf->role_name_prefix = NULL;
	conf->resource_name_prefix = NULL;
	conf->user_decoration = NULL;

	return conf;
}

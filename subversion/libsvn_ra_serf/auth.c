/* auth.c:  ra_serf authentication handling
 *
 * ====================================================================
 * Copyright (c) 2007 CollabNet.  All rights reserved.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution.  The terms
 * are also available at http://subversion.tigris.org/license-1.html.
 * If newer versions of this license are posted there, you may use a
 * newer version instead, at your option.
 *
 * This software consists of voluntary contributions made by many
 * individuals.  For exact contribution history, see the revision
 * history and logs, available at http://subversion.tigris.org/.
 * ====================================================================
 */

/*** Includes. ***/

#include <serf.h>
#include <apr_base64.h>

#include "ra_serf.h"
#include "win32_auth_sspi.h"
#include "svn_private_config.h"

/*** Forward declarations. ***/

static svn_error_t *
handle_basic_auth(svn_ra_serf__session_t *session,
                  svn_ra_serf__connection_t *conn,
                  serf_request_t *request,
                  serf_bucket_t *response,
                  char *auth_hdr,
                  char *auth_attr,
                  apr_pool_t *pool);

static svn_error_t *
init_basic_connection(svn_ra_serf__session_t *session,
                      svn_ra_serf__connection_t *conn,
                      apr_pool_t *pool);

static svn_error_t *
setup_request_basic_auth(svn_ra_serf__connection_t *conn,
                         serf_bucket_t *hdrs_bkt);

static svn_error_t *
handle_proxy_basic_auth(svn_ra_serf__session_t *session,
                        svn_ra_serf__connection_t *conn,
                        serf_request_t *request,
                        serf_bucket_t *response,
                        char *auth_hdr,
                        char *auth_attr,
                        apr_pool_t *pool);

static svn_error_t *
init_proxy_basic_connection(svn_ra_serf__session_t *session,
                            svn_ra_serf__connection_t *conn,
                            apr_pool_t *pool);

static svn_error_t *
setup_request_proxy_basic_auth(svn_ra_serf__connection_t *conn,
                               serf_bucket_t *hdrs_bkt);

/*** Global variables. ***/
static const svn_ra_serf__auth_protocol_t serf_auth_protocols[] = {
  {
    401,
    "Basic",
    init_basic_connection,
    handle_basic_auth,
    setup_request_basic_auth,
  },
  {
    407,
    "Basic",
    init_proxy_basic_connection,
    handle_proxy_basic_auth,
    setup_request_proxy_basic_auth,
  },
#ifdef SVN_RA_SERF_SSPI_ENABLED
  {
    401,
    "NTLM",
    init_sspi_connection,
    handle_sspi_auth,
    setup_request_sspi_auth,
  },
  {
    407,
    "NTLM",
    init_proxy_sspi_connection,
    handle_proxy_sspi_auth,
    setup_request_proxy_sspi_auth,
  },
#endif /* SVN_RA_SERF_SSPI_ENABLED */

  /* ADD NEW AUTHENTICATION IMPLEMENTATIONS HERE (as they're written) */

  /* sentinel */
  { 0 }
};

/*** Code. ***/

/**
 * base64 encode the authentication data and build an authentication
 * header in this format:
 * [PROTOCOL] [BASE64 AUTH DATA]
 */
void
svn_ra_serf__encode_auth_header(const char * protocol, char **header,
                                const char * data, apr_size_t data_len,
                                apr_pool_t *pool)
{
  apr_size_t encoded_len, proto_len;
  char * ptr;

  encoded_len = apr_base64_encode_len(data_len);
  proto_len = strlen(protocol);

  *header = apr_palloc(pool, encoded_len + proto_len + 1);
  ptr = *header;

  apr_cpystrn(ptr, protocol, proto_len + 1);
  ptr += proto_len;
  *ptr++ = ' ';

  apr_base64_encode(ptr, data, data_len);
}


/* Dispatch authentication handling based on server <-> proxy authentication
   and the list of allowed authentication schemes as passed back from the
   server or proxy in the Authentication headers. */
svn_error_t *
svn_ra_serf__handle_auth(int code,
                         svn_ra_serf__session_t *session,
                         svn_ra_serf__connection_t *conn,
                         serf_request_t *request,
                         serf_bucket_t *response,
                         apr_pool_t *pool)
{
  serf_bucket_t *hdrs;
  const svn_ra_serf__auth_protocol_t *prot = NULL;
  char *auth_name = NULL, *auth_attr, *auth_hdr=NULL, *header, *header_attr;
  svn_error_t *cached_err = SVN_NO_ERROR;

  hdrs = serf_bucket_response_get_headers(response);
  if (code == 401)
    auth_hdr = (char*)serf_bucket_headers_get(hdrs, "WWW-Authenticate");
  else if (code == 407)
    auth_hdr = (char*)serf_bucket_headers_get(hdrs, "Proxy-Authenticate");

  if (!auth_hdr)
    {
      if (session->auth_protocol)
        return svn_error_createf(SVN_ERR_AUTHN_FAILED, NULL,
                                 "%s Authentication failed",
                                 session->auth_protocol->auth_name);
      else
        return svn_error_create(SVN_ERR_AUTHN_FAILED, NULL, NULL);
    }

  /* If multiple *-Authenticate headers are found, serf will combine them into
     one header, with the values separated by a comma. */
  header = apr_strtok(auth_hdr, ",", &header_attr);

  while (header)
    {
      svn_boolean_t proto_found = FALSE;
      auth_name = apr_strtok(header, " ", &auth_attr);

      cached_err = SVN_NO_ERROR;

      /* Find the matching authentication handler.
         Note that we don't reuse the auth protocol stored in the session,
         as that may have changed. (ex. fallback from ntlm to basic.) */
      for (prot = serf_auth_protocols; prot->code != 0; ++prot)
        {
          if (code == prot->code && strcasecmp(auth_name, prot->auth_name) == 0)
            {
              svn_serf__auth_handler_func_t handler = prot->handle_func;
              svn_error_t *err = NULL;

              /* If this is the first time we use this protocol in this session,
                 make sure to initialize the authentication part of the session
                 first. */
              if (code == 401 && session->auth_protocol != prot)
                {
                  err = prot->init_conn_func(session, conn, session->pool);
                  if (err == SVN_NO_ERROR)
                    session->auth_protocol = prot;
                  else
                    session->auth_protocol = NULL;
                }
             else if (code == 407 && session->proxy_auth_protocol != prot)
                {
                  err = prot->init_conn_func(session, conn, session->pool);
                  if (err == SVN_NO_ERROR)
                    session->proxy_auth_protocol = prot;
                  else
                    session->proxy_auth_protocol = NULL;
                }

              if (err == SVN_NO_ERROR)
                {
                  proto_found = TRUE;
                  err = handler(session, conn, request, response,
                                header, auth_attr, session->pool);
                }
              if (err)
                {
                  /* If authentication fails, cache the error for now. Try the
                     next available scheme. If there's none raise the error. */
                  proto_found = FALSE;
                  prot = NULL;
                  if (cached_err)
                    svn_error_clear(cached_err);
                  cached_err = err;
                }

              break;
            }
        }
      if (proto_found)
        break;

      /* Try the next Authentication header. */
      header = apr_strtok(NULL, ",", &header_attr);
    }

  SVN_ERR(cached_err);

  if (!prot || prot->auth_name == NULL)
    {
      /* Support more authentication mechanisms. */
      return svn_error_createf(SVN_ERR_AUTHN_FAILED, NULL,
                               "%s authentication not supported.\n"
                               "Authentication failed", auth_name);
    }

  return SVN_NO_ERROR;
}

static svn_error_t *
handle_basic_auth(svn_ra_serf__session_t *session,
                  svn_ra_serf__connection_t *conn,
                  serf_request_t *request,
                  serf_bucket_t *response,
                  char *auth_hdr,
                  char *auth_attr,
                  apr_pool_t *pool)
{
  void *creds;
  char *last, *realm_name;
  svn_auth_cred_simple_t *simple_creds;
  const char *tmp;
  apr_size_t tmp_len;
  apr_port_t port;
  int i;

  if (!session->realm)
    {
      char *attr;

      attr = apr_strtok(auth_attr, "=", &last);
      if (strcasecmp(attr, "realm") == 0)
        {
          realm_name = apr_strtok(NULL, "=", &last);
          if (realm_name[0] == '\"')
            {
              apr_size_t realm_len;

              realm_len = strlen(realm_name);
              if (realm_name[realm_len - 1] == '\"')
                {
                  realm_name[realm_len - 1] = '\0';
                  realm_name++;
                }
            }
        }
      else
        {
          return svn_error_create
            (SVN_ERR_RA_DAV_MALFORMED_DATA, NULL,
             _("Missing 'realm' attribute in Authorization header"));
        }
      if (!realm_name)
        {
          return svn_error_create
            (SVN_ERR_RA_DAV_MALFORMED_DATA, NULL,
             _("Missing 'realm' attribute in Authorization header"));
        }

      if (session->repos_url.port_str)
        {
          port = session->repos_url.port;
        }
      else
        {
          port = apr_uri_port_of_scheme(session->repos_url.scheme);
        }

      session->realm = apr_psprintf(session->pool, "<%s://%s:%d> %s",
                                    session->repos_url.scheme,
                                    session->repos_url.hostname,
                                    port,
                                    realm_name);
    }

  /* Use svn_auth_first_credentials if this is the first time we ask for
     credentials during this session OR if the last time we asked
     session->auth_state wasn't set (eg. if the credentials provider was
     cancelled by the user). */
  if (!session->auth_state)
    {
      SVN_ERR(svn_auth_first_credentials(&creds,
                                         &session->auth_state,
                                         SVN_AUTH_CRED_SIMPLE,
                                         session->realm,
                                         session->wc_callbacks->auth_baton,
                                         session->pool));
    }
  else
    {
      SVN_ERR(svn_auth_next_credentials(&creds,
                                        session->auth_state,
                                        session->pool));
    }

  session->auth_attempts++;

  if (!creds || session->auth_attempts > 4)
    {
      /* No more credentials. */
      return svn_error_create(SVN_ERR_AUTHN_FAILED, NULL,
                "No more credentials or we tried too many times.\n"
                "Authentication failed");
    }

  simple_creds = creds;

  tmp = apr_pstrcat(session->pool,
                    simple_creds->username, ":", simple_creds->password, NULL);
  tmp_len = strlen(tmp);

  svn_ra_serf__encode_auth_header(session->auth_protocol->auth_name,
                                  &session->auth_value, tmp, tmp_len, pool);
  session->auth_header = "Authorization";

  /* FIXME Come up with a cleaner way of changing the connection auth. */
  for (i = 0; i < session->num_conns; i++)
    {
      session->conns[i]->auth_header = session->auth_header;
      session->conns[i]->auth_value = session->auth_value;
    }

  return SVN_NO_ERROR;
}

static svn_error_t *
init_basic_connection(svn_ra_serf__session_t *session,
                      svn_ra_serf__connection_t *conn,
                      apr_pool_t *pool)
{
  conn->auth_header = session->auth_header;
  conn->auth_value = session->auth_value;

  return SVN_NO_ERROR;
}

static svn_error_t *
setup_request_basic_auth(svn_ra_serf__connection_t *conn,
                         serf_bucket_t *hdrs_bkt)
{
  /* Take the default authentication header for this connection, if any. */
  if (conn->auth_header && conn->auth_value)
    {
      serf_bucket_headers_setn(hdrs_bkt, conn->auth_header, conn->auth_value);
    }

  return SVN_NO_ERROR;
}

static svn_error_t *
handle_proxy_basic_auth(svn_ra_serf__session_t *session,
                        svn_ra_serf__connection_t *conn,
                        serf_request_t *request,
                        serf_bucket_t *response,
                        char *auth_hdr,
                        char *auth_attr,
                        apr_pool_t *pool)
{
  const char *tmp;
  apr_size_t tmp_len;
  int i;

  tmp = apr_pstrcat(session->pool,
                    session->proxy_username, ":",
                    session->proxy_password, NULL);
  tmp_len = strlen(tmp);

  session->proxy_auth_attempts++;

  if (session->proxy_auth_attempts > 1)
    {
      /* No more credentials. */
      return svn_error_create(SVN_ERR_AUTHN_FAILED, NULL,
                "Proxy authentication failed");
    }

  svn_ra_serf__encode_auth_header(session->proxy_auth_protocol->auth_name,
                                  &session->proxy_auth_value,
                                  tmp, tmp_len, pool);
  session->proxy_auth_header = "Proxy-Authorization";

  /* FIXME Come up with a cleaner way of changing the connection auth. */
  for (i = 0; i < session->num_conns; i++)
    {
      session->conns[i]->proxy_auth_header = session->proxy_auth_header;
      session->conns[i]->proxy_auth_value = session->proxy_auth_value;
    }

  return SVN_NO_ERROR;
}

static svn_error_t *
init_proxy_basic_connection(svn_ra_serf__session_t *session,
                            svn_ra_serf__connection_t *conn,
                            apr_pool_t *pool)
{
  conn->proxy_auth_header = session->proxy_auth_header;
  conn->proxy_auth_value = session->proxy_auth_value;

  return SVN_NO_ERROR;
}

static svn_error_t *
setup_request_proxy_basic_auth(svn_ra_serf__connection_t *conn,
                               serf_bucket_t *hdrs_bkt)
{
  /* Take the default authentication header for this connection, if any. */
  if (conn->proxy_auth_header && conn->proxy_auth_value)
    {
      serf_bucket_headers_setn(hdrs_bkt, conn->proxy_auth_header,
                               conn->proxy_auth_value);
    }

  return SVN_NO_ERROR;
}

/*
 * win32_auth_sspi.c : authn implementation through SSPI
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

/* TODO:
   - remove NTLM dependency so we can reuse SSPI for Kerberos later. */

/*
 * NTLM authentication for HTTP
 *
 * 1. C  --> S:    GET
 *
 *    C <--  S:    401 Authentication Required
 *                 WWW-Authenticate: NTLM
 *
 * -> Initialize the NTLM authentication handler.
 *
 * 2. C  --> S:    GET
 *                 Authorization: NTLM <Base64 encoded Type 1 message>
 *                 sspi_ctx->state = sspi_auth_in_progress;
 *
 *    C <--  S:    401 Authentication Required
 *                 WWW-Authenticate: NTLM <Base64 encoded Type 2 message>
 *
 * 3. C  --> S:    GET
 *                 Authorization: NTLM <Base64 encoded Type 3 message>
 *                 sspi_ctx->state = sspi_auth_completed;
 *
 *    C <--  S:    200 Ok
 *
 * This handshake is required for every new connection. If the handshake is
 * completed successfully, all other requested on the same connection will
 * be authenticated without needing to pass the WWW-Authenticate header.
 *
 * Note: Step 1 of the handshake will only happen on the first connection, once
 * we know the server requires NTLM authentication, the initial requests on the
 * other connections will include the NTLM Type 1 message, so we start at
 * step 2 in the handshake.
 */

/*** Includes ***/
#include <string.h>

#include <apr.h>
#include <apr_base64.h>

#include "svn_error.h"

#include "ra_serf.h"
#include "win32_auth_sspi.h"

#include "private/svn_atomic.h"

#ifdef SVN_RA_SERF_SSPI_ENABLED

/*** Global variables ***/
static svn_atomic_t sspi_initialized = 0;
static PSecurityFunctionTable sspi = NULL;
static unsigned int ntlm_maxtokensize = 0;

/* Loads the SSPI function table we can use to call SSPI's public functions.
 * Accepted by svn_atomic__init_once()
 */
static svn_error_t *
initialize_sspi(apr_pool_t* pool)
{
  sspi = InitSecurityInterface();

  if (sspi)
    return SVN_NO_ERROR;

  return svn_error_createf
          (SVN_ERR_RA_SERF_SSPI_INITIALISATION_FAILED, NULL,
           "SSPI Initialization failed.");
}

/* Calculates the maximum token size based on the authentication protocol. */
static svn_error_t *
sspi_maxtokensize(char *auth_pkg, unsigned int *maxtokensize)
{
  SECURITY_STATUS status;
  SecPkgInfo *sec_pkg_info = NULL;

  status = sspi->QuerySecurityPackageInfo(auth_pkg,
                                          &sec_pkg_info);
  if (status == SEC_E_OK)
    {
      *maxtokensize = sec_pkg_info->cbMaxToken;
      sspi->FreeContextBuffer(sec_pkg_info);
    }
  else
    return svn_error_createf
      (SVN_ERR_RA_SERF_SSPI_INITIALISATION_FAILED, NULL,
       "SSPI Initialization failed.");

  return SVN_NO_ERROR;
}

svn_error_t *
init_sspi_connection(svn_ra_serf__session_t *session,
                     svn_ra_serf__connection_t *conn,
                     apr_pool_t *pool)
{
  const char *tmp;
  apr_size_t tmp_len;

  SVN_ERR(svn_atomic__init_once(&sspi_initialized, initialize_sspi, pool));

  conn->sspi_context = (serf_sspi_context_t*)
    apr_palloc(pool, sizeof(serf_sspi_context_t));
  conn->sspi_context->ctx.dwLower = 0;
  conn->sspi_context->ctx.dwUpper = 0;
  conn->sspi_context->state = sspi_auth_not_started;

  /* Setup the initial request to the server with an SSPI header */
  SVN_ERR(sspi_get_credentials(NULL, 0, &tmp, &tmp_len,
                               conn->sspi_context));
  svn_ra_serf__encode_auth_header("NTLM", &conn->auth_value, tmp, tmp_len,
                                  pool);
  conn->auth_header = "Authorization";

  /* Make serf send the initial requests one by one */
  serf_connection_set_max_outstanding_requests(conn->conn, 1);

  return SVN_NO_ERROR;
}

svn_error_t *
handle_sspi_auth(svn_ra_serf__session_t *session,
                 svn_ra_serf__connection_t *conn,
                 serf_request_t *request,
                 serf_bucket_t *response,
                 char *auth_hdr,
                 char *auth_attr,
                 apr_pool_t *pool)
{
  const char *tmp;
  char *base64_token, *token = NULL, *last;
  apr_size_t tmp_len, token_len = 0;

  base64_token = apr_strtok(auth_attr, " ", &last);
  if (base64_token)
    {
      token_len = apr_base64_decode_len(base64_token);
      token = apr_palloc(pool, token_len);
      apr_base64_decode(token, base64_token);
    }

  /* We can get a whole batch of 401 responses from the server, but we should
     only start the authentication phase once, so if we started authentication
     ignore all responses with initial NTLM authentication header. */
  if (!token && conn->sspi_context->state != sspi_auth_not_started)
    return SVN_NO_ERROR;

  SVN_ERR(sspi_get_credentials(token, token_len, &tmp, &tmp_len,
                               conn->sspi_context));

  svn_ra_serf__encode_auth_header(session->auth_protocol->auth_name,
                                  &conn->auth_value, tmp, tmp_len, pool);
  conn->auth_header = "Authorization";

  /* If the handshake is finished tell serf it can send as much requests as it
     likes. */
  if (conn->sspi_context->state == sspi_auth_completed)
    serf_connection_set_max_outstanding_requests(conn->conn, 0);

  return SVN_NO_ERROR;
}

svn_error_t *
setup_request_sspi_auth(svn_ra_serf__connection_t *conn,
                        serf_bucket_t *hdrs_bkt)
{
  /* Take the default authentication header for this connection, if any. */
  if (conn->auth_header && conn->auth_value)
    {
      serf_bucket_headers_setn(hdrs_bkt, conn->auth_header, conn->auth_value);
      conn->auth_header = NULL;
      conn->auth_value = NULL;
    }

  return SVN_NO_ERROR;
}

svn_error_t *
sspi_get_credentials(char *token, apr_size_t token_len, const char **buf,
                     apr_size_t *buf_len, serf_sspi_context_t *sspi_ctx)
{
  SecBuffer in_buf, out_buf;
  SecBufferDesc in_buf_desc, out_buf_desc;
  SECURITY_STATUS status;
  DWORD ctx_attr;
  TimeStamp expires;
  CredHandle creds;
  char *target = NULL;
  CtxtHandle *ctx = &(sspi_ctx->ctx);

  if (ntlm_maxtokensize == 0)
    sspi_maxtokensize("NTLM", &ntlm_maxtokensize);
  /* Prepare inbound buffer. */
  in_buf.BufferType = SECBUFFER_TOKEN;
  in_buf.cbBuffer   = token_len;
  in_buf.pvBuffer   = token;
  in_buf_desc.cBuffers  = 1;
  in_buf_desc.ulVersion = SECBUFFER_VERSION;
  in_buf_desc.pBuffers  = &in_buf;

  /* Prepare outbound buffer. */
  out_buf.BufferType = SECBUFFER_TOKEN;
  out_buf.cbBuffer   = ntlm_maxtokensize;
  out_buf.pvBuffer   = (char*)malloc(ntlm_maxtokensize);
  out_buf_desc.cBuffers  = 1;
  out_buf_desc.ulVersion = SECBUFFER_VERSION;
  out_buf_desc.pBuffers  = &out_buf;

  /* Try to accept the server token. */
  status = sspi->AcquireCredentialsHandle(NULL, /* current user */
                                          "NTLM",
                                          SECPKG_CRED_OUTBOUND,
                                          NULL, NULL,
                                          NULL, NULL,
                                          &creds,
                                          &expires);

  if (status != SEC_E_OK)
    return svn_error_createf
            (SVN_ERR_RA_SERF_SSPI_INITIALISATION_FAILED, NULL,
             "SSPI Initialization failed.");

  status = sspi->InitializeSecurityContext(&creds,
                                           ctx != NULL && ctx->dwLower != 0
                                             ? ctx
                                             : NULL,
                                           target,
                                           ISC_REQ_REPLAY_DETECT |
                                           ISC_REQ_SEQUENCE_DETECT |
                                           ISC_REQ_CONFIDENTIALITY |
                                           ISC_REQ_DELEGATE,
                                           0,
                                           SECURITY_NATIVE_DREP,
                                           &in_buf_desc,
                                           0,
                                           ctx,
                                           &out_buf_desc,
                                           &ctx_attr,
                                           &expires);

  /* Finish authentication if SSPI requires so. */
  if (status == SEC_I_COMPLETE_NEEDED
      || status == SEC_I_COMPLETE_AND_CONTINUE)
    {
      if (sspi->CompleteAuthToken != NULL)
        sspi->CompleteAuthToken(ctx, &out_buf_desc);
    }

  *buf = out_buf.pvBuffer;
  *buf_len = out_buf.cbBuffer;

  switch (status)
    {
      case SEC_E_OK:
      case SEC_I_COMPLETE_NEEDED:
          sspi_ctx->state = sspi_auth_completed;
          break;

      case SEC_I_CONTINUE_NEEDED:
      case SEC_I_COMPLETE_AND_CONTINUE:
          sspi_ctx->state = sspi_auth_in_progress;
          break;

      default:
          return svn_error_createf(SVN_ERR_AUTHN_FAILED, NULL,
                "Authentication failed with error 0x%x.", status);
    }

  return SVN_NO_ERROR;
}

/* Proxy authentication */

svn_error_t *
init_proxy_sspi_connection(svn_ra_serf__session_t *session,
                           svn_ra_serf__connection_t *conn,
                           apr_pool_t *pool)
{
  const char *tmp;
  apr_size_t tmp_len;

  SVN_ERR(svn_atomic__init_once(&sspi_initialized, initialize_sspi, pool));

  conn->proxy_sspi_context = (serf_sspi_context_t*)
    apr_palloc(pool, sizeof(serf_sspi_context_t));
  conn->proxy_sspi_context->ctx.dwLower = 0;
  conn->proxy_sspi_context->ctx.dwUpper = 0;
  conn->proxy_sspi_context->state = sspi_auth_not_started;

  /* Setup the initial request to the server with an SSPI header */
  SVN_ERR(sspi_get_credentials(NULL, 0, &tmp, &tmp_len,
                               conn->proxy_sspi_context));
  svn_ra_serf__encode_auth_header("NTLM", &conn->proxy_auth_value, tmp,
                                  tmp_len,
                                  pool);
  conn->proxy_auth_header = "Proxy-Authorization";

  /* Make serf send the initial requests one by one */
  serf_connection_set_max_outstanding_requests(conn->conn, 1);

  return SVN_NO_ERROR;
}

svn_error_t *
handle_proxy_sspi_auth(svn_ra_serf__session_t *session,
                       svn_ra_serf__connection_t *conn,
                       serf_request_t *request,
                       serf_bucket_t *response,
                       char *auth_hdr,
                       char *auth_attr,
                       apr_pool_t *pool)
{
  const char *tmp;
  char *base64_token, *token = NULL, *last;
  apr_size_t tmp_len, token_len = 0;

  base64_token = apr_strtok(auth_attr, " ", &last);
  if (base64_token)
    {
      token_len = apr_base64_decode_len(base64_token);
      token = apr_palloc(pool, token_len);
      apr_base64_decode(token, base64_token);
    }

  /* We can get a whole batch of 401 responses from the server, but we should
     only start the authentication phase once, so if we started authentication
     ignore all responses with initial NTLM authentication header. */
  if (!token && conn->proxy_sspi_context->state != sspi_auth_not_started)
    return SVN_NO_ERROR;

  SVN_ERR(sspi_get_credentials(token, token_len, &tmp, &tmp_len,
                               conn->proxy_sspi_context));

  svn_ra_serf__encode_auth_header(session->proxy_auth_protocol->auth_name,
                                  &conn->proxy_auth_value, tmp, tmp_len, pool);
  conn->proxy_auth_header = "Proxy-Authorization";

  /* If the handshake is finished tell serf it can send as much requests as it
     likes. */
  if (conn->proxy_sspi_context->state == sspi_auth_completed)
    serf_connection_set_max_outstanding_requests(conn->conn, 0);

  return SVN_NO_ERROR;
}

svn_error_t *
setup_request_proxy_sspi_auth(svn_ra_serf__connection_t *conn,
                              serf_bucket_t *hdrs_bkt)
{
  /* Take the default authentication header for this connection, if any. */
  if (conn->proxy_auth_header && conn->proxy_auth_value)
    {
      serf_bucket_headers_setn(hdrs_bkt, conn->proxy_auth_header,
                               conn->proxy_auth_value);
      conn->proxy_auth_header = NULL;
      conn->proxy_auth_value = NULL;
    }

  return SVN_NO_ERROR;
}

#endif /* SVN_RA_SERF_SSPI_ENABLED */

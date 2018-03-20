#include <stdio.h>
#include <stdlib.h>
#include "ndpi_define.h"
void parse_packet_line_info(char *payload, int payload_len)
{
  u_int32_t a;
  u_int16_t end = payload_len - 1;

  for(a = 0; a < end-1 /* This because get_u_int16_t(packet->payload, a) reads 2 bytes */; a++) {
    if(get_u_int16_t(payload, a) == ntohs(0x0d0a)) { /* If end of line char sequence CR+NL "\r\n", process line */
      packet->line[packet->parsed_lines].len = (u_int16_t)(((unsigned long) &packet->payload[a]) - ((unsigned long) packet->line[packet->parsed_lines].ptr));

      /* First line of a HTTP response parsing. Expected a "HTTP/1.? ???" */
      if(packet->parsed_lines == 0 && packet->line[0].len >= NDPI_STATICSTRING_LEN("HTTP/1.X 200 ") &&
	     strncasecmp((const char *)packet->line[0].ptr, "HTTP/1.", NDPI_STATICSTRING_LEN("HTTP/1.")) == 0 &&
	     packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.X ")] > '0' && /* response code between 000 and 699 */
	     packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.X ")] < '6') {

	    packet->http_response.ptr = &packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.1 ")];
	    packet->http_response.len = packet->line[0].len - NDPI_STATICSTRING_LEN("HTTP/1.1 ");
	    packet->http_num_headers++;

	    /* Set server HTTP response code */
	    strncpy((char*)flow->http.response_status_code, (char*)packet->http_response.ptr, 3);
	    flow->http.response_status_code[4]='\0';


	    NDPI_LOG_DBG2(ndpi_struct,
		  "ndpi_parse_packet_line_info: HTTP response parsed: \"%.*s\"\n",
		   packet->http_response.len, packet->http_response.ptr);
      }
      /* "Server:" header line in HTTP response */
      if(packet->line[packet->parsed_lines].len > NDPI_STATICSTRING_LEN("Server:") + 1
	     && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Server:", NDPI_STATICSTRING_LEN("Server:")) == 0) {
	    // some stupid clients omit a space and place the servername directly after the colon
        if(packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:")] == ' ') {
          packet->server_line.ptr =
            &packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:") + 1];
          packet->server_line.len =
            packet->line[packet->parsed_lines].len - (NDPI_STATICSTRING_LEN("Server:") + 1);
        } else {
          packet->server_line.ptr = &packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:")];
          packet->server_line.len = packet->line[packet->parsed_lines].len - NDPI_STATICSTRING_LEN("Server:");
        }
        packet->http_num_headers++;
      }
      /* "Host:" header line in HTTP request */
      if(packet->line[packet->parsed_lines].len > 6
	 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr,
			     "Host:", 5) == 0) {
        // some stupid clients omit a space and place the hostname directly after the colon
        if(packet->line[packet->parsed_lines].ptr[5] == ' ') {
          packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[6];
          packet->host_line.len = packet->line[packet->parsed_lines].len - 6;
        } else {
          packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[5];
          packet->host_line.len = packet->line[packet->parsed_lines].len - 5;
        }
        packet->http_num_headers++;
      }
      /* "X-Forwarded-For:" header line in HTTP request. Commonly used for HTTP proxies. */
      if(packet->line[packet->parsed_lines].len > 17
	     && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "X-Forwarded-For:", 16) == 0) {
        // some stupid clients omit a space and place the hostname directly after the colon
        if(packet->line[packet->parsed_lines].ptr[16] == ' ') {
          packet->forwarded_line.ptr = &packet->line[packet->parsed_lines].ptr[17];
          packet->forwarded_line.len = packet->line[packet->parsed_lines].len - 17;
        } else {
          packet->forwarded_line.ptr = &packet->line[packet->parsed_lines].ptr[16];
          packet->forwarded_line.len = packet->line[packet->parsed_lines].len - 16;
        }
        packet->http_num_headers++;
      }
      /* "Content-Type:" header line in HTTP. */
      if(packet->line[packet->parsed_lines].len > 14
	     && (strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Content-Type: ", 14) == 0
	         || strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Content-type: ", 14) == 0)) {
        packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[14];
        packet->content_line.len = packet->line[packet->parsed_lines].len - 14;
        packet->http_num_headers++;
      }
      /* "Content-Type:" header line in HTTP AGAIN. Probably a bogus response without space after ":" */
      if(packet->line[packet->parsed_lines].len > 13
	     && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Content-type:", 13) == 0) {
        packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[13];
        packet->content_line.len = packet->line[packet->parsed_lines].len - 13;
        packet->http_num_headers++;
      }
      /* "Accept:" header line in HTTP request. */
      if(packet->line[packet->parsed_lines].len > 8
	     && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Accept: ", 8) == 0) {
        packet->accept_line.ptr = &packet->line[packet->parsed_lines].ptr[8];
        packet->accept_line.len = packet->line[packet->parsed_lines].len - 8;
        packet->http_num_headers++;
      }
      /* "Referer:" header line in HTTP request. */
      if(packet->line[packet->parsed_lines].len > 9
	     && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Referer: ", 9) == 0) {
        packet->referer_line.ptr = &packet->line[packet->parsed_lines].ptr[9];
        packet->referer_line.len = packet->line[packet->parsed_lines].len - 9;
        packet->http_num_headers++;
      }
      /* "User-Agent:" header line in HTTP request. */
      if(packet->line[packet->parsed_lines].len > 12
	     && (strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "User-Agent: ", 12) == 0
	         || strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "User-agent: ", 12) == 0)) {
        packet->user_agent_line.ptr = &packet->line[packet->parsed_lines].ptr[12];
        packet->user_agent_line.len = packet->line[packet->parsed_lines].len - 12;
        packet->http_num_headers++;
      }
      /* "Content-Encoding:" header line in HTTP response (and request?). */
      if(packet->line[packet->parsed_lines].len > 18
	     && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Content-Encoding: ", 18) == 0) {
        packet->http_encoding.ptr = &packet->line[packet->parsed_lines].ptr[18];
        packet->http_encoding.len = packet->line[packet->parsed_lines].len - 18;
        packet->http_num_headers++;
      }
      /* "Transfer-Encoding:" header line in HTTP. */
      if(packet->line[packet->parsed_lines].len > 19
	     && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Transfer-Encoding: ", 19) == 0) {
        packet->http_transfer_encoding.ptr = &packet->line[packet->parsed_lines].ptr[19];
        packet->http_transfer_encoding.len = packet->line[packet->parsed_lines].len - 19;
        packet->http_num_headers++;
      }
      /* "Content-Length:" header line in HTTP. */
      if(packet->line[packet->parsed_lines].len > 16
	     && ((strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Content-Length: ", 16) == 0)
	     || (strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "content-length: ", 16) == 0))) {
        packet->http_contentlen.ptr = &packet->line[packet->parsed_lines].ptr[16];
        packet->http_contentlen.len = packet->line[packet->parsed_lines].len - 16;
        packet->http_num_headers++;
      }
      /* "Cookie:" header line in HTTP. */
      if(packet->line[packet->parsed_lines].len > 8
	     && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Cookie: ", 8) == 0) {
        packet->http_cookie.ptr = &packet->line[packet->parsed_lines].ptr[8];
        packet->http_cookie.len = packet->line[packet->parsed_lines].len - 8;
        packet->http_num_headers++;
      }
      /* "Origin:" header line in HTTP. */
      if(packet->line[packet->parsed_lines].len > 8
	     && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Origin: ", 8) == 0) {
        packet->http_origin.ptr = &packet->line[packet->parsed_lines].ptr[8];
        packet->http_origin.len = packet->line[packet->parsed_lines].len - 8;
        packet->http_num_headers++;
      }
      /* "X-Session-Type:" header line in HTTP. */
      if(packet->line[packet->parsed_lines].len > 16
	     && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "X-Session-Type: ", 16) == 0) {
        packet->http_x_session_type.ptr = &packet->line[packet->parsed_lines].ptr[16];
        packet->http_x_session_type.len = packet->line[packet->parsed_lines].len - 16;
        packet->http_num_headers++;
      }
      /* Identification and counting of other HTTP headers.
       * We consider the most common headers, but there are many others,
       * which can be seen at references below:
       * - https://tools.ietf.org/html/rfc7230
       * - https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
       */
      if((packet->line[packet->parsed_lines].len >  6 && ( strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Date: ", 6) == 0 ||
                                                           strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Vary: ", 6) == 0 ||
                                                           strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "ETag: ", 6) == 0 )) ||
         (packet->line[packet->parsed_lines].len >  8 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Pragma: ", 8) == 0) ||
         (packet->line[packet->parsed_lines].len >  9 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Expires: ", 9) == 0) ||
         (packet->line[packet->parsed_lines].len > 12 && ( strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Set-Cookie: ", 12) == 0 ||
                                                           strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Keep-Alive: ", 12) == 0 ||
                                                           strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Connection: ", 12) == 0)) ||
         (packet->line[packet->parsed_lines].len > 15 && ( strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Last-Modified: ", 15) == 0 ||
                                                           strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Accept-Ranges: ", 15) == 0)) ||
         (packet->line[packet->parsed_lines].len > 17 && ( strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Accept-Language: ", 17) == 0 ||
                                                           strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Accept-Encoding: ", 17) == 0)) ||
         (packet->line[packet->parsed_lines].len > 27 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Upgrade-Insecure-Requests: ", 27) == 0)) {
        /* Just count. In the future, if needed, this if can be splited to parse these headers */
        packet->http_num_headers++;
      }


      if(packet->line[packet->parsed_lines].len == 0) {
        packet->empty_line_position = a;
        packet->empty_line_position_set = 1;
      }

      if(packet->parsed_lines >= (NDPI_MAX_PARSE_LINES_PER_PACKET - 1))
        return;

      packet->parsed_lines++;
      packet->line[packet->parsed_lines].ptr = &packet->payload[a + 2];
      packet->line[packet->parsed_lines].len = 0;

      if((a + 2) >= packet->payload_packet_len)
	    return;

      a++; /* next char in the payload */
    }
  }

  if(packet->parsed_lines >= 1) {
    packet->line[packet->parsed_lines].len
      = (u_int16_t)(((unsigned long) &packet->payload[packet->payload_packet_len]) -
		    ((unsigned long) packet->line[packet->parsed_lines].ptr));
    packet->parsed_lines++;
  }
}

int is_http_response_header(char *payload, int payload_len){
	
	char *response = payload;
	int len = payload_len;
	int i = 0, j = 0;
	
	for (i=0; i< payload_len-4; i++) {
		
	}
}

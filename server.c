#include <ev.h>
#include <fcntl.h>
#include "list.h"
#include "server.h"
#include "http_parser.h"

static struct http_parser_settings parser_settings = {
	.on_message_begin = 	null_cb,
	.on_message_complete = 	null_cb,
	.on_headers_complete = 	null_cb,
	.on_header_field     = 	header_field_cb,
	.on_header_value     = 	header_value_cb,
	.on_url              = 	url_cb,
	.on_body             = 	body_cb
};

static int null_cb(http_parser_t *parser)
{
	return 0;
}

static int header_field_cb(http_parser_t *parser, const char *buf, size_t len)
{
	struct http_request *request = (struct http_request*)parser->data;
	struct http_header *header = add_http_header(request);
	alloc_cpy(header->name, buff, len);
	return 0;
}

static int header_value_cb(http_parser_t *parser, const char *buf, size_t len)
{
	struct http_request *request = (struct http_request*)parser->data;
	struct http_header *header = request->header;
	while(header->next != NULL){
		header = header->next;
	}
	alloc_cpy(header->value, buf, len);
	return 0;
}

int body_cb(http_parser *parser, const char *buf, size_t len) {
    struct http_request *request = (struct http_request *) parser->data;
    alloc_cpy(request->body, buf, len)
    return 0;
}

int url_cb(http_parser *parser, const char *buf, size_t len) {
    struct http_request *request = (struct http_request *) parser->data;
    request->method = parser->method;
    request->http_major = parser->http_major;
    request->http_minor = parser->http_minor;
    alloc_cpy(request->url, buf, len)
    return 0;
}


static inline struct http_header *new_http_header()
{
	struct http_header *header = malloc(sizeof(struct http_header));
	memset(header, 0, sizeof(struct http_header));
}

static inline struct http_header *add_http_header(struct http_request *request)
{
	struct http_header *header = request->header;
	while(header != NULL){
		if(header->next == NULL){
			header->next = new_http_header();
			return header->next;
		}
		header = header->next;
	}
	request->headers = new_http_header();
	return request->header;
}

static inline int setnonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if(flags < 0)
		return flags;
	flags |= O_NONBLOCK;
	if(fcntl(fd, F_SETFL, flags) < 0)
		return -1;

	return 0;
}

static inline struct http_request* new_http_request()
{
	struct http_request *request = malloc(sizeof(struct http_request));
	memset(request, 0, sizeof(struct http_request));
	return request;
}

void delete_http_request(struct http_request *request)
{
	
}

size_t http_parser_excute(http_parser_t *parser, 
						const http_parser_settings *settings, 
						const char *data, 
						size_t len)
{
	char c, ch;
	int8_t unhex_val;
	const char *p = data;
	const char *header_field_mark = 0;
	const char *header_value_mark = 0;
	const char *url_mark = 0;
	const char *body_mark = 0;
	const char *status_mark = 0;
	enum state p_state = (enum state)parser->state;

	if(HTTP_PARSER_ERRNO(parser) != HPE_OK){
		return 0;
	}

	if(len == 0){
		switch(CURRENT_STATE()){
			case s_body_identity_eof:
	        /* Use of CALLBACK_NOTIFY() here would erroneously return 1 byte read if
	         * we got paused.
	         */
	        CALLBACK_NOTIFY_NOADVANCE(message_complete);
	        return 0;

	      	case s_dead:
	      	case s_start_req_or_res:
	      	case s_start_res:
	      	case s_start_req:
	        	return 0;

	      	default:
	        	SET_ERRNO(HPE_INVALID_EOF_STATE);
	        	return 1;
		}
	}

	if(CURRENT_STATE() == s_header_field)
		header_field_mark = data;
	if(CURRENT_STATE() == s_header_value)
		header_value_mark = data;
	switch(CURRENT_STATE()){
		case s_req_path:
		case s_req_schema:
		case s_req_schema_slash:
		case s_req_schema_slash_slash:
		case s_req_server_start:
		case s_req_server:
		case s_req_server_with_at:
		case s_req_query_string_start:
		case s_req_query_string:
		case s_req_fragment_start:
		case s_req_fragment:
			url_mark = data;
			break;
		case s_res_status:
		    status_mark = data;
		    break;
		default:
		    break;
	}

	for(p = data; p != data + len; p++){
		char = *p;

		if(PARSING_HEADER(CURRENT_STATE()))
			COUNT_HEADER_SIZE(1);
reexecute:
		switch(CURRENT_STATE()){
			case s_dead:
				 /* this state is used after a 'Connection: close' message
         			* the parser will error out if it reads another message
         		*/
         		if(likely(ch == CR || ch == CF))
					break;
				SET_ERRNO(HPE_CLOSED_CONNECTION);
			 	goto error;
			case s_start_req_or_res:
				if(ch == CR || ch == CF)
					break;
				 parser->flags = 0;
        		 parser->content_length = ULLONG_MAX;

        		if (ch == 'H') {
          		UPDATE_STATE(s_res_or_resp_H);

          		CALLBACK_NOTIFY(message_begin);
        		} else {
          			parser->type = HTTP_REQUEST;
          			UPDATE_STATE(s_start_req);
          			REEXECUTE();
        		}
        		break;
		 	case s_res_or_resp_h:
				if (ch == 'T') {
          			parser->type = HTTP_RESPONSE;
          			UPDATE_STATE(s_res_HT);
        		} else {
         		 if (UNLIKELY(ch != 'E')) {
            		SET_ERRNO(HPE_INVALID_CONSTANT);
            		goto error;
          		}
          			parser->type = HTTP_REQUEST;
          			parser->method = HTTP_HEAD;
          			parser->index = 2;
          			UPDATE_STATE(s_req_method);
        		}
        		break;
			case s_start_res:
		        parser->flags = 0;
		        parser->content_length = ULLONG_MAX;

		        switch (ch) {
		          case 'H':
		            UPDATE_STATE(s_res_H);
		            break;

		          case CR:
		          case LF:
		            break;

		          default:
		            SET_ERRNO(HPE_INVALID_CONSTANT);
		            goto error;
		        }

		        CALLBACK_NOTIFY(message_begin);
		        break;	
			case s_res_H:
				STRICT_CHECK(ch != 'T');
		        UPDATE_STATE(s_res_HT);
		        break;
			case s_res_HT:
				STRICT_CHECK(ch != 'T');
		        UPDATE_STATE(s_res_HTT);
		        break;
			case s_res_HTT:
				STRICT_CHECK(ch != 'P');
        		UPDATE_STATE(s_res_HTTP);
        		break;
			case s_res_HTTP:
				STRICT_CHECK(ch != '/');
        		UPDATE_STATE(s_res_first_http_major);
        		break;
			case s_res_first_http_major:
				if (UNLIKELY(ch < '0' || ch > '9')) {
          			SET_ERRNO(HPE_INVALID_VERSION);
          			goto error;
        		}

        		parser->http_major = ch - '0';
        		UPDATE_STATE(s_res_http_major);
        		break;
			case s_res_http_major:  
		        if (ch == '.') {
		          UPDATE_STATE(s_res_first_http_minor);
		          break;
		        }

		        if (!IS_NUM(ch)) {
		          SET_ERRNO(HPE_INVALID_VERSION);
		          goto error;
		        }

		        parser->http_major *= 10;
		        parser->http_major += ch - '0';

		        if (UNLIKELY(parser->http_major > 999)) {
		          SET_ERRNO(HPE_INVALID_VERSION);
		          goto error;
		        }
		        break;
			case s_res_first_http_minor:
				if (UNLIKELY(!IS_NUM(ch))) {
		          SET_ERRNO(HPE_INVALID_VERSION);
		          goto error;
		        }

		        parser->http_minor = ch - '0';
		        UPDATE_STATE(s_res_http_minor);
		        break;
		     case s_res_http_minor:			 	
		        if (ch == ' ') {
		          UPDATE_STATE(s_res_first_status_code);
		          break;
		        }

		        if (UNLIKELY(!IS_NUM(ch))) {
		          SET_ERRNO(HPE_INVALID_VERSION);
		          goto error;
		        }

		        parser->http_minor *= 10;
		        parser->http_minor += ch - '0';

		        if (UNLIKELY(parser->http_minor > 999)) {
		          SET_ERRNO(HPE_INVALID_VERSION);
		          goto error;
		        }
		        break;
			case s_res_first_status_code:				     
		        if (!IS_NUM(ch)) {
		          if (ch == ' ') {
		            break;
		          }

		          SET_ERRNO(HPE_INVALID_STATUS);
		          goto error;
		        }
		        parser->status_code = ch - '0';
		        UPDATE_STATE(s_res_status_code);
		        break;
      		case s_res_status_code:
		        if (!IS_NUM(ch)) {
		          switch (ch) {
		            case ' ':
		              UPDATE_STATE(s_res_status_start);
		              break;
		            case CR:
		              UPDATE_STATE(s_res_line_almost_done);
		              break;
		            case LF:
		              UPDATE_STATE(s_header_field_start);
		              break;
		            default:
		              SET_ERRNO(HPE_INVALID_STATUS);
		              goto error;
		          }
		          break;
		        }

		        parser->status_code *= 10;
		        parser->status_code += ch - '0';

		        if (UNLIKELY(parser->status_code > 999)) {
		          SET_ERRNO(HPE_INVALID_STATUS);
		          goto error;
		        }

		        break;
			case s_res_status_start:
		        if (ch == CR) {
		          UPDATE_STATE(s_res_line_almost_done);
		          break;
		        }

		        if (ch == LF) {
		          UPDATE_STATE(s_header_field_start);
		          break;
		        }

		        MARK(status);
		        UPDATE_STATE(s_res_status);
		        parser->index = 0;
		        break;
			case s_res_status:
				if (ch == CR) {
		          UPDATE_STATE(s_res_line_almost_done);
		          CALLBACK_DATA(status);
		          break;
		        }

		        if (ch == LF) {
		          UPDATE_STATE(s_header_field_start);
		          CALLBACK_DATA(status);
		          break;
		        }

		        break;
			case s_res_line_almost_done:
				STRICT_CHECK(ch != LF);
		        UPDATE_STATE(s_header_field_start);
		        break;
			case s_start_req:
		        if (ch == CR || ch == LF)
		          break;
		        parser->flags = 0;
		        parser->content_length = ULLONG_MAX;

		        if (UNLIKELY(!IS_ALPHA(ch))) {
		          SET_ERRNO(HPE_INVALID_METHOD);
		          goto error;
		        }

		        parser->method = (enum http_method) 0;
		        parser->index = 1;
		        switch (ch) {
		          case 'C': parser->method = HTTP_CONNECT; /* or COPY, CHECKOUT */ break;
		          case 'D': parser->method = HTTP_DELETE; break;
		          case 'G': parser->method = HTTP_GET; break;
		          case 'H': parser->method = HTTP_HEAD; break;
		          case 'L': parser->method = HTTP_LOCK; break;
		          case 'M': parser->method = HTTP_MKCOL; /* or MOVE, MKACTIVITY, MERGE, M-SEARCH, MKCALENDAR */ break;
		          case 'N': parser->method = HTTP_NOTIFY; break;
		          case 'O': parser->method = HTTP_OPTIONS; break;
		          case 'P': parser->method = HTTP_POST;
		            /* or PROPFIND|PROPPATCH|PUT|PATCH|PURGE */
		            break;
		          case 'R': parser->method = HTTP_REPORT; break;
		          case 'S': parser->method = HTTP_SUBSCRIBE; /* or SEARCH */ break;
		          case 'T': parser->method = HTTP_TRACE; break;
		          case 'U': parser->method = HTTP_UNLOCK; /* or UNSUBSCRIBE */ break;
		          default:
		            SET_ERRNO(HPE_INVALID_METHOD);
		            goto error;
		        }
		        UPDATE_STATE(s_req_method);

		        CALLBACK_NOTIFY(message_begin);

		        break;
			case s_req_method:
	        	const char *matcher;
		        if (UNLIKELY(ch == '\0')) {
		          SET_ERRNO(HPE_INVALID_METHOD);
		          goto error;
		        }

		        matcher = method_strings[parser->method];
		        if (ch == ' ' && matcher[parser->index] == '\0') {
		          UPDATE_STATE(s_req_spaces_before_url);
		        } else if (ch == matcher[parser->index]) {
		          ; /* nada */
		        } else if (parser->method == HTTP_CONNECT) {
		          if (parser->index == 1 && ch == 'H') {
		            parser->method = HTTP_CHECKOUT;
		          } else if (parser->index == 2  && ch == 'P') {
		            parser->method = HTTP_COPY;
		          } else {
		            SET_ERRNO(HPE_INVALID_METHOD);
		            goto error;
		          }
		        } else if (parser->method == HTTP_MKCOL) {
		          if (parser->index == 1 && ch == 'O') {
		            parser->method = HTTP_MOVE;
		          } else if (parser->index == 1 && ch == 'E') {
		            parser->method = HTTP_MERGE;
		          } else if (parser->index == 1 && ch == '-') {
		            parser->method = HTTP_MSEARCH;
		          } else if (parser->index == 2 && ch == 'A') {
		            parser->method = HTTP_MKACTIVITY;
		          } else if (parser->index == 3 && ch == 'A') {
		            parser->method = HTTP_MKCALENDAR;
		          } else {
		            SET_ERRNO(HPE_INVALID_METHOD);
		            goto error;
		          }
		        } else if (parser->method == HTTP_SUBSCRIBE) {
		          if (parser->index == 1 && ch == 'E') {
		            parser->method = HTTP_SEARCH;
		          } else {
		            SET_ERRNO(HPE_INVALID_METHOD);
		            goto error;
		          }
		        } else if (parser->index == 1 && parser->method == HTTP_POST) {
		          if (ch == 'R') {
		            parser->method = HTTP_PROPFIND; /* or HTTP_PROPPATCH */
		          } else if (ch == 'U') {
		            parser->method = HTTP_PUT; /* or HTTP_PURGE */
		          } else if (ch == 'A') {
		            parser->method = HTTP_PATCH;
		          } else {
		            SET_ERRNO(HPE_INVALID_METHOD);
		            goto error;
		          }
		        } else if (parser->index == 2) {
		          if (parser->method == HTTP_PUT) {
		            if (ch == 'R') {
		              parser->method = HTTP_PURGE;
		            } else {
		              SET_ERRNO(HPE_INVALID_METHOD);
		              goto error;
		            }
		          } else if (parser->method == HTTP_UNLOCK) {
		            if (ch == 'S') {
		              parser->method = HTTP_UNSUBSCRIBE;
		            } else {
		              SET_ERRNO(HPE_INVALID_METHOD);
		              goto error;
		            }
		          } else {
		            SET_ERRNO(HPE_INVALID_METHOD);
		            goto error;
		          }
		        } else if (parser->index == 4 && parser->method == HTTP_PROPFIND && ch == 'P') {
		          parser->method = HTTP_PROPPATCH;
		        } else {
		          SET_ERRNO(HPE_INVALID_METHOD);
		          goto error;
		        }

		        ++parser->index;
		        break;
			case s_req_spaces_before_url:
		        if (ch == ' ') break;

		        MARK(url);
		        if (parser->method == HTTP_CONNECT) {
		          UPDATE_STATE(s_req_server_start);
		        }

		        UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));
		        if (UNLIKELY(CURRENT_STATE() == s_dead)) {
		          SET_ERRNO(HPE_INVALID_URL);
		          goto error;
		        }

		        break;
			case s_req_schema:
			case s_req_schema_slash:
      		case s_req_schema_slash_slash:
			case s_req_server_start:
		        switch (ch) {
		          /* No whitespace allowed here */
		          case ' ':
		          case CR:
		          case LF:
		            SET_ERRNO(HPE_INVALID_URL);
		            goto error;
		          default:
		            UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));
		            if (UNLIKELY(CURRENT_STATE() == s_dead)) {
		              SET_ERRNO(HPE_INVALID_URL);
		              goto error;
		            }
		        }

		        break;
			case s_req_server:
			case s_req_server:
	      	case s_req_server_with_at:
	      	case s_req_path:
	      	case s_req_query_string_start:
	      	case s_req_query_string:
	      	case s_req_fragment_start:
	      	case s_req_fragment:
		        switch (ch) {
		          case ' ':
		            UPDATE_STATE(s_req_http_start);
		            CALLBACK_DATA(url);
		            break;
		          case CR:
		          case LF:
		            parser->http_major = 0;
		            parser->http_minor = 9;
		            UPDATE_STATE((ch == CR) ?
		              s_req_line_almost_done :
		              s_header_field_start);
		            CALLBACK_DATA(url);
		            break;
		          default:
		            UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));
		            if (UNLIKELY(CURRENT_STATE() == s_dead)) {
		              SET_ERRNO(HPE_INVALID_URL);
		              goto error;
		            }
		        }
		        break;
			case s_req_http_start:
			  switch (ch) {
		          case 'H':
		            UPDATE_STATE(s_req_http_H);
		            break;
		          case ' ':
		            break;
		          default:
		            SET_ERRNO(HPE_INVALID_CONSTANT);
		            goto error;
	          }
	          break;
			case s_req_http_H:
				STRICT_CHECK(ch != 'T');
		        UPDATE_STATE(s_req_http_HT);
		        break;
			case s_req_http_HT:
				STRICT_CHECK(ch != 'T');
        		UPDATE_STATE(s_req_http_HTT);
        		break;
			case s_req_http_HTT:
				STRICT_CHECK(ch != 'P');
        		UPDATE_STATE(s_req_http_HTTP);
        		break;
			case s_req_http_HTTP:
				STRICT_CHECK(ch != '/');
        		UPDATE_STATE(s_req_first_http_major);
        		break;
			case s_req_first_http_major:
				if (UNLIKELY(ch < '1' || ch > '9')) {
          			SET_ERRNO(HPE_INVALID_VERSION);
          			goto error;
        		}

        		parser->http_major = ch - '0';
        		UPDATE_STATE(s_req_http_major);
        		break;
			case s_req_http_major:
		        if (ch == '.') {
		          UPDATE_STATE(s_req_first_http_minor);
		          break;
		        }

		        if (UNLIKELY(!IS_NUM(ch))) {
		          SET_ERRNO(HPE_INVALID_VERSION);
		          goto error;
		        }

		        parser->http_major *= 10;
		        parser->http_major += ch - '0';

		        if (UNLIKELY(parser->http_major > 999)) {
		          SET_ERRNO(HPE_INVALID_VERSION);
		          goto error;
		        }

		        break;
			case s_req_first_http_minor:
				if (UNLIKELY(!IS_NUM(ch))) {
          			SET_ERRNO(HPE_INVALID_VERSION);
          			goto error;
        		}

        		parser->http_minor = ch - '0';
        		UPDATE_STATE(s_req_http_minor);
        		break;
			case s_req_http_minor:
		        if (ch == CR) {
		          UPDATE_STATE(s_req_line_almost_done);
		          break;
		        }

		        if (ch == LF) {
		          UPDATE_STATE(s_header_field_start);
		          break;
		        }

		        /* XXX allow spaces after digit? */

		        if (UNLIKELY(!IS_NUM(ch))) {
		          SET_ERRNO(HPE_INVALID_VERSION);
		          goto error;
		        }

		        parser->http_minor *= 10;
		        parser->http_minor += ch - '0';

		        if (UNLIKELY(parser->http_minor > 999)) {
		          SET_ERRNO(HPE_INVALID_VERSION);
		          goto error;
		        }

		        break;
			case s_req_line_almost_done:
		        if (UNLIKELY(ch != LF)) {
		          SET_ERRNO(HPE_LF_EXPECTED);
		          goto error;
		        }

		        UPDATE_STATE(s_header_field_start);
		        break;
			case s_header_field_start:
		        if (ch == CR) {
		          UPDATE_STATE(s_headers_almost_done);
		          break;
		        }

		        if (ch == LF) {
		          /* they might be just sending \n instead of \r\n so this would be
		           * the second \n to denote the end of headers*/
		          UPDATE_STATE(s_headers_almost_done);
		          REEXECUTE();
		        }

		        c = TOKEN(ch);

		        if (UNLIKELY(!c)) {
		          SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
		          goto error;
		        }

		        MARK(header_field);

		        parser->index = 0;
		        UPDATE_STATE(s_header_field);

		        switch (c) {
		          case 'c':
		            parser->header_state = h_C;
		            break;

		          case 'p':
		            parser->header_state = h_matching_proxy_connection;
		            break;

		          case 't':
		            parser->header_state = h_matching_transfer_encoding;
		            break;

		          case 'u':
		            parser->header_state = h_matching_upgrade;
		            break;

		          default:
		            parser->header_state = h_general;
		            break;
		        }
		        break;
			case s_header_field:
		        const char* start = p;
		        for (; p != data + len; p++) {
		          ch = *p;
		          c = TOKEN(ch);

		          if (!c)
		            break;

		          switch (parser->header_state) {
		            case h_general:
		              break;

		            case h_C:
		              parser->index++;
		              parser->header_state = (c == 'o' ? h_CO : h_general);
		              break;

		            case h_CO:
		              parser->index++;
		              parser->header_state = (c == 'n' ? h_CON : h_general);
		              break;

		            case h_CON:
		              parser->index++;
		              switch (c) {
		                case 'n':
		                  parser->header_state = h_matching_connection;
		                  break;
		                case 't':
		                  parser->header_state = h_matching_content_length;
		                  break;
		                default:
		                  parser->header_state = h_general;
		                  break;
		              }
		          }
		        }
		              break;
			case s_header_value_discard_ws:
				if (ch == ' ' || ch == '\t') break;

		        if (ch == CR) {
		          UPDATE_STATE(s_header_value_discard_ws_almost_done);
		          break;
		        }

		        if (ch == LF) {
		          UPDATE_STATE(s_header_value_discard_lws);
		          break;
		        }
			case s_header_value_start:
		        MARK(header_value);

		        UPDATE_STATE(s_header_value);
		        parser->index = 0;

		        c = LOWER(ch);

		        switch (parser->header_state) {
		          case h_upgrade:
		            parser->flags |= F_UPGRADE;
		            parser->header_state = h_general;
		            break;

		          case h_transfer_encoding:
		            /* looking for 'Transfer-Encoding: chunked' */
		            if ('c' == c) {
		              parser->header_state = h_matching_transfer_encoding_chunked;
		            } else {
		              parser->header_state = h_general;
		            }
		            break;

		          case h_content_length:
		            if (UNLIKELY(!IS_NUM(ch))) {
		              SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
		              goto error;
		            }

		            parser->content_length = ch - '0';
		            break;

		          case h_connection:
		            /* looking for 'Connection: keep-alive' */
		            if (c == 'k') {
		              parser->header_state = h_matching_connection_keep_alive;
		            /* looking for 'Connection: close' */
		            } else if (c == 'c') {
		              parser->header_state = h_matching_connection_close;
		            } else if (c == 'u') {
		              parser->header_state = h_matching_connection_upgrade;
		            } else {
		              parser->header_state = h_matching_connection_token;
		            }
		            break;

		          /* Multi-value `Connection` header */
		          case h_matching_connection_token_start:
		            break;

		          default:
		            parser->header_state = h_general;
		            break;
		        }
		        break;
			case s_header_value:
		        const char* start = p;
		        enum header_states h_state = (enum header_states) parser->header_state;
		        for (; p != data + len; p++) {
		          ch = *p;
		          if (ch == CR) {
		            UPDATE_STATE(s_header_almost_done);
		            parser->header_state = h_state;
		            CALLBACK_DATA(header_value);
		            break;
		          }

		          if (ch == LF) {
		            UPDATE_STATE(s_header_almost_done);
		            COUNT_HEADER_SIZE(p - start);
		            parser->header_state = h_state;
		            CALLBACK_DATA_NOADVANCE(header_value);
		            REEXECUTE();
		          }

		          c = LOWER(ch);

		          switch (h_state) {
		            case h_general:
		            {
		              const char* p_cr;
		              const char* p_lf;
		              size_t limit = data + len - p;

		              limit = MIN(limit, HTTP_MAX_HEADER_SIZE);

		              p_cr = (const char*) memchr(p, CR, limit);
		              p_lf = (const char*) memchr(p, LF, limit);
		              if (p_cr != NULL) {
		                if (p_lf != NULL && p_cr >= p_lf)
		                  p = p_lf;
		                else
		                  p = p_cr;
		              } else if (UNLIKELY(p_lf != NULL)) {
		                p = p_lf;
		              } else {
		                p = data + len;
		              }
		              --p;

		              break;
		            }

		            case h_connection:
		            case h_transfer_encoding:
		              assert(0 && "Shouldn't get here.");
		              break;

		            case h_content_length:
		            {
		              uint64_t t;

		              if (ch == ' ') break;

		              if (UNLIKELY(!IS_NUM(ch))) {
		                SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
		                parser->header_state = h_state;
		                goto error;
		              }

		              t = parser->content_length;
		              t *= 10;
		              t += ch - '0';

		              /* Overflow? Test against a conservative limit for simplicity. */
		              if (UNLIKELY((ULLONG_MAX - 10) / 10 < parser->content_length)) {
		                SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
		                parser->header_state = h_state;
		                goto error;
		              }

		              parser->content_length = t;
		              break;
		            }

		            /* Transfer-Encoding: chunked */
		            case h_matching_transfer_encoding_chunked:
		              parser->index++;
		              if (parser->index > sizeof(CHUNKED)-1
		                  || c != CHUNKED[parser->index]) {
		                h_state = h_general;
		              } else if (parser->index == sizeof(CHUNKED)-2) {
		                h_state = h_transfer_encoding_chunked;
		              }
		              break;

		            case h_matching_connection_token_start:
		              /* looking for 'Connection: keep-alive' */
		              if (c == 'k') {
		                h_state = h_matching_connection_keep_alive;
		              /* looking for 'Connection: close' */
		              } else if (c == 'c') {
		                h_state = h_matching_connection_close;
		              } else if (c == 'u') {
		                h_state = h_matching_connection_upgrade;
		              } else if (STRICT_TOKEN(c)) {
		                h_state = h_matching_connection_token;
		              } else if (c == ' ' || c == '\t') {
		                /* Skip lws */
		              } else {
		                h_state = h_general;
		              }
		              break;

		            /* looking for 'Connection: keep-alive' */
		            case h_matching_connection_keep_alive:
		              parser->index++;
		              if (parser->index > sizeof(KEEP_ALIVE)-1
		                  || c != KEEP_ALIVE[parser->index]) {
		                h_state = h_matching_connection_token;
		              } else if (parser->index == sizeof(KEEP_ALIVE)-2) {
		                h_state = h_connection_keep_alive;
		              }
		              break;

		            /* looking for 'Connection: close' */
		            case h_matching_connection_close:
		              parser->index++;
		              if (parser->index > sizeof(CLOSE)-1 || c != CLOSE[parser->index]) {
		                h_state = h_matching_connection_token;
		              } else if (parser->index == sizeof(CLOSE)-2) {
		                h_state = h_connection_close;
		              }
		              break;

		            /* looking for 'Connection: upgrade' */
		            case h_matching_connection_upgrade:
		              parser->index++;
		              if (parser->index > sizeof(UPGRADE) - 1 ||
		                  c != UPGRADE[parser->index]) {
		                h_state = h_matching_connection_token;
		              } else if (parser->index == sizeof(UPGRADE)-2) {
		                h_state = h_connection_upgrade;
		              }
		              break;

		            case h_matching_connection_token:
		              if (ch == ',') {
		                h_state = h_matching_connection_token_start;
		                parser->index = 0;
		              }
		              break;

		            case h_transfer_encoding_chunked:
		              if (ch != ' ') h_state = h_general;
		              break;

		            case h_connection_keep_alive:
		            case h_connection_close:
		            case h_connection_upgrade:
		              if (ch == ',') {
		                if (h_state == h_connection_keep_alive) {
		                  parser->flags |= F_CONNECTION_KEEP_ALIVE;
		                } else if (h_state == h_connection_close) {
		                  parser->flags |= F_CONNECTION_CLOSE;
		                } else if (h_state == h_connection_upgrade) {
		                  parser->flags |= F_CONNECTION_UPGRADE;
		                }
		                h_state = h_matching_connection_token_start;
		                parser->index = 0;
		              } else if (ch != ' ') {
		                h_state = h_matching_connection_token;
		              }
		              break;

		            default:
		              UPDATE_STATE(s_header_value);
		              h_state = h_general;
		              break;
		          }
		        }
		        parser->header_state = h_state;

		        COUNT_HEADER_SIZE(p - start);

		        if (p == data + len)
		          --p;
		        break;
			case s_header_almost_done:
		        STRICT_CHECK(ch != LF);

		        UPDATE_STATE(s_header_value_lws);
		        break;

			case s_header_value_lws:
		        if (ch == ' ' || ch == '\t') {
		          UPDATE_STATE(s_header_value_start);
		          REEXECUTE();
		        }

		        /* finished the header */
		        switch (parser->header_state) {
		          case h_connection_keep_alive:
		            parser->flags |= F_CONNECTION_KEEP_ALIVE;
		            break;
		          case h_connection_close:
		            parser->flags |= F_CONNECTION_CLOSE;
		            break;
		          case h_transfer_encoding_chunked:
		            parser->flags |= F_CHUNKED;
		            break;
		          case h_connection_upgrade:
		            parser->flags |= F_CONNECTION_UPGRADE;
		            break;
		          default:
		            break;
		        }

		        UPDATE_STATE(s_header_field_start);
		        REEXECUTE();
			case s_header_value_discard_ws_almost_done:
		        STRICT_CHECK(ch != LF);
		        UPDATE_STATE(s_header_value_discard_lws);
		        break;
			case s_header_value_discard_lws:
		        if (ch == ' ' || ch == '\t') {
		          UPDATE_STATE(s_header_value_discard_ws);
		          break;
		        } else {
		          switch (parser->header_state) {
		            case h_connection_keep_alive:
		              parser->flags |= F_CONNECTION_KEEP_ALIVE;
		              break;
		            case h_connection_close:
		              parser->flags |= F_CONNECTION_CLOSE;
		              break;
		            case h_connection_upgrade:
		              parser->flags |= F_CONNECTION_UPGRADE;
		              break;
		            case h_transfer_encoding_chunked:
		              parser->flags |= F_CHUNKED;
		              break;
		            default:
		              break;
		          }

		          /* header value was empty */
		          MARK(header_value);
		          UPDATE_STATE(s_header_field_start);
		          CALLBACK_DATA_NOADVANCE(header_value);
		          REEXECUTE();
		        }
		  case s_header_almost_done:
		        STRICT_CHECK(ch != LF);

		        if (parser->flags & F_TRAILING) {
		          /* End of a chunked request */
		          UPDATE_STATE(NEW_MESSAGE());
		          CALLBACK_NOTIFY(message_complete);
		          break;
		        }

		        UPDATE_STATE(s_headers_done);

		        /* Set this here so that on_headers_complete() callbacks can see it */
		        parser->upgrade =
		          ((parser->flags & (F_UPGRADE | F_CONNECTION_UPGRADE)) ==
		           (F_UPGRADE | F_CONNECTION_UPGRADE) ||
		           parser->method == HTTP_CONNECT);

		        /* Here we call the headers_complete callback. This is somewhat
		         * different than other callbacks because if the user returns 1, we
		         * will interpret that as saying that this message has no body. This
		         * is needed for the annoying case of recieving a response to a HEAD
		         * request.
		         *
		         * We'd like to use CALLBACK_NOTIFY_NOADVANCE() here but we cannot, so
		         * we have to simulate it by handling a change in errno below.
		         */
		        if (settings->on_headers_complete) {
		          switch (settings->on_headers_complete(parser)) {
		            case 0:
		              break;

		            case 1:
		              parser->flags |= F_SKIPBODY;
		              break;

		            default:
		              SET_ERRNO(HPE_CB_headers_complete);
		              RETURN(p - data); /* Error */
		          }
		        }

		        if (HTTP_PARSER_ERRNO(parser) != HPE_OK) {
		          RETURN(p - data);
		        }

		        REEXECUTE();
				
			case s_headers_done:
		        STRICT_CHECK(ch != LF);

		        parser->nread = 0;

		        /* Exit, the rest of the connect is in a different protocol. */
		        if (parser->upgrade) {
		          UPDATE_STATE(NEW_MESSAGE());
		          CALLBACK_NOTIFY(message_complete);
		          RETURN((p - data) + 1);
		        }

		        if (parser->flags & F_SKIPBODY) {
		          UPDATE_STATE(NEW_MESSAGE());
		          CALLBACK_NOTIFY(message_complete);
		        } else if (parser->flags & F_CHUNKED) {
		          /* chunked encoding - ignore Content-Length header */
		          UPDATE_STATE(s_chunk_size_start);
		        } else {
		          if (parser->content_length == 0) {
		            /* Content-Length header given but zero: Content-Length: 0\r\n */
		            UPDATE_STATE(NEW_MESSAGE());
		            CALLBACK_NOTIFY(message_complete);
		          } else if (parser->content_length != ULLONG_MAX) {
		            /* Content-Length header given and non-zero */
		            UPDATE_STATE(s_body_identity);
		          } else {
		            if (parser->type == HTTP_REQUEST ||
		                !http_message_needs_eof(parser)) {
		              /* Assume content-length 0 - read the next */
		              UPDATE_STATE(NEW_MESSAGE());
		              CALLBACK_NOTIFY(message_complete);
		            } else {
		              /* Read body until EOF */
		              UPDATE_STATE(s_body_identity_eof);
		            }
		          }
		        }

		        break;
			case s_body_identity:
		        uint64_t to_read = MIN(parser->content_length,
		                               (uint64_t) ((data + len) - p));

		        assert(parser->content_length != 0
		            && parser->content_length != ULLONG_MAX);

		        /* The difference between advancing content_length and p is because
		         * the latter will automaticaly advance on the next loop iteration.
		         * Further, if content_length ends up at 0, we want to see the last
		         * byte again for our message complete callback.
		         */
		        MARK(body);
		        parser->content_length -= to_read;
		        p += to_read - 1;

		        if (parser->content_length == 0) {
		          UPDATE_STATE(s_message_done);

		          /* Mimic CALLBACK_DATA_NOADVANCE() but with one extra byte.
		           *
		           * The alternative to doing this is to wait for the next byte to
		           * trigger the data callback, just as in every other case. The
		           * problem with this is that this makes it difficult for the test
		           * harness to distinguish between complete-on-EOF and
		           * complete-on-length. It's not clear that this distinction is
		           * important for applications, but let's keep it for now.
		           */
		          CALLBACK_DATA_(body, p - body_mark + 1, p - data);
		          REEXECUTE();
		        }

		        break;
			case s_body_identity_eof:
				MARK(body);
		        p = data + len - 1;

		        break;
			case s_message_done:
				UPDATE_STATE(NEW_MESSAGE());
		        CALLBACK_NOTIFY(message_complete);
		        break;
			case s_chunk_size_start:
		        assert(parser->nread == 1);
		        assert(parser->flags & F_CHUNKED);

		        unhex_val = unhex[(unsigned char)ch];
		        if (UNLIKELY(unhex_val == -1)) {
		          SET_ERRNO(HPE_INVALID_CHUNK_SIZE);
		          goto error;
		        }

		        parser->content_length = unhex_val;
		        UPDATE_STATE(s_chunk_size);
		        break;
			case s_chunk_size:
		        uint64_t t;

		        assert(parser->flags & F_CHUNKED);

		        if (ch == CR) {
		          UPDATE_STATE(s_chunk_size_almost_done);
		          break;
		        }

		        unhex_val = unhex[(unsigned char)ch];

		        if (unhex_val == -1) {
		          if (ch == ';' || ch == ' ') {
		            UPDATE_STATE(s_chunk_parameters);
		            break;
		          }

		          SET_ERRNO(HPE_INVALID_CHUNK_SIZE);
		          goto error;
		        }

		        t = parser->content_length;
		        t *= 16;
		        t += unhex_val;

		        /* Overflow? Test against a conservative limit for simplicity. */
		        if (UNLIKELY((ULLONG_MAX - 16) / 16 < parser->content_length)) {
		          SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
		          goto error;
		        }

		        parser->content_length = t;
		        break;
			case s_chunk_parameters:
		        assert(parser->flags & F_CHUNKED);
		        /* just ignore this shit. TODO check for overflow */
		        if (ch == CR) {
		          UPDATE_STATE(s_chunk_size_almost_done);
		          break;
		        }
		        break;
			case s_chunk_size_almost_done:
		        assert(parser->flags & F_CHUNKED);
		        STRICT_CHECK(ch != LF);

		        parser->nread = 0;

		        if (parser->content_length == 0) {
		          parser->flags |= F_TRAILING;
		          UPDATE_STATE(s_header_field_start);
		        } else {
		          UPDATE_STATE(s_chunk_data);
		        }
		        break;
			case s_chunk_data:
		        uint64_t to_read = MIN(parser->content_length,
		                               (uint64_t) ((data + len) - p));

		        assert(parser->flags & F_CHUNKED);
		        assert(parser->content_length != 0
		            && parser->content_length != ULLONG_MAX);

		        /* See the explanation in s_body_identity for why the content
		         * length and data pointers are managed this way.
		         */
		        MARK(body);
		        parser->content_length -= to_read;
		        p += to_read - 1;

		        if (parser->content_length == 0) {
		          UPDATE_STATE(s_chunk_data_almost_done);
		        }

		        break;
			case s_chunk_data_almost_done:
				assert(parser->flags & F_CHUNKED);
		        assert(parser->content_length == 0);
		        STRICT_CHECK(ch != CR);
		        UPDATE_STATE(s_chunk_data_done);
		        CALLBACK_DATA(body);
		        break;
			case s_chunk_data_done:
				assert(parser->flags & F_CHUNKED);
		        STRICT_CHECK(ch != LF);
		        parser->nread = 0;
		        UPDATE_STATE(s_chunk_size_start);
		        break;
			default:
				assert(0 && "unhandled state");
		        SET_ERRNO(HPE_INVALID_INTERNAL_STATE);
		        goto error;
     
	}
}
}

static struct http_request* parse_request(char *request_data, int len)
{
	http_parser_t *parser = malloc(sizeof(http_parser_t));
	http_parser_init(parser, HTTP_REQUEST);
	struct http_request *request = new_http_request();
	request->data = request;
	int ret = http_parser_excute(parser, &parser_settings, request_data, len);
	if(ret == len){
		if(http_should_keep_alive(parser)){
			request->flags |= F_HREQ_KEEPALIVE;
		}
		free(parser);
		return request;
	}
	delete_http_request(request)
	free(parser);
	return NULL;
}

static void write_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	if(!(revents & EV_WRITE)){
		ev_io_stop(EV_A_ w);
		return;
	}

	struct client *client = (struct client*)((char *)w - offsetof(struct client,  ev_write));
	struct http_request *request = client->request;
	if(!request){
		write(client->fd, "HTTP/1.1 400 Bad Request\r\n\r\n", 24);
		close(client->fd);
		free(client->request_data);
		free(client);
	}

	client->handle_request(request, client->fd);
	delete_http_request(request);
	free(client->request_data);
	free(client);
	ev_io_stop(EV_A_ w);
}

static void read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	int len = 0, sum = 0;
	if(!(revents & EV_READ)){
		ev_io_stop(EV_A_ w);;
		return;
	}
	struct client *client = 
		(struct client*)((char *)w - offsetof(struct client, ev_read));

	char *buff[REQUEST_BUFFER_SIZE + 1];
	client->request_data = NULL;

	do{
		len = read(client->fd, buff, REQUEST_BUFFER_SIZE);
		sum += len;
		if(len  < REQUEST_BUFFER_SIZE)
			buff[len] = '\0';
		if(client->request_data == NULL){
			client->request_data = malloc(len + 1);
			memcpy(client->request_data,  buff, len);
		}else{
			client->request_data = realloc(client->request_data, sum + 1);
			memcpy(client->request_data+sum-len, buff, len);
		}
	}while(len == REQUEST_BUFFER_SIZE);
	client->request = NULL;
	client->request = parse_request(client->request_data, sum);
	ev_io_stop(EV_A_ w);
	ev_io_init(&client->ev_write, write_cb, client->fd, EV_WRITE);
	ev_io_start(loop, &client->ev_write);
}


static void accept_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct client* main_client = 
		(struct client*)((char *)w - offsetof(struct client, ev_accept));
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(struct sockaddr_in);
	int  client_fd = accept(w->fd, (struct sockaddr*)&client_addr, &client_len);
	if(client_fd  < 0){
		return;
	}

	if(setnonblock(client_fd) < 0){
		return;
	}

	struct client *client = malloc(sizeof(struct client));

	client->handle_request = main_client->handle_request;
	client->data = main_client->data;
	client->fd = client_fd;

	ev_io_init(&client->ev_read, read_cb, client->fd, EV_READ);
	ev_io_start(loop, &client->ev_read);
}

int http_server_loop(struct http_server *server, int fd)
{
	server->loop = ev_default_loop(0);
	server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(server->listen_fd < 0){
		perror("listen failed(socket)");
		return -1;
	}

	int reuseaddr_on = 1;
	if(setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on, sizeof(server->listen_addr)) < 0){
			perror("setsockopt failed");
			return -1;
	}

	struct sockaddr *listen_addr = (struct sockaddr*)&server->listen_addr;

	if(bind(server->listen_fd, listen_addr, sizeof(*listen_addr)) < 0){
		perror("bind failed");
		return -1;
	}

	if(listen(server->listen_fd, 5) < 0){
		perror("listen failed");
		return -1;
	}

	if(setnonblock(server->listen_fd) < 0){
		perror("setnonblock failed");
		return -1;
	}

	struct client *main_client = malloc(sizeof(struct client));
	if(!main_client){
		perror("malloc failed");
		return -1;
	}
	memset(main_client, 0, sizeof(struct client));
	main_client->handle_request = server->handle_request;
	main_client->data = server->data;
	ev_io_init(&main_client->ev_accept, accept_cb, server->listen_fd, EV_READ);
	ev_io_start(server->loop, &main_client->ev_accept);
	server->ev_accept = &main_client->ev_accept;
	ev_loop(server->loop, 0);

	return 0;
}

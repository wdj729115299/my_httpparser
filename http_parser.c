#include "http_parser.h"
void http_parser_init(http_parser *parser, http_parser_type_e type)
{
	void *data = parser->data;
	memset(parser, 0, sizeof(http_parser));
	parser->data = data;
	parser->type = type;
	parser->state = (type == HTTP_REQUEST? s_start_seq : 
		(type == HTTP_RESPONSE? s_start_res : s_start_req_or_res));
	parser->http_errno = HPE_OK;
}

int http_should_keep_alive(const http_parser_t *parser)
{
	if(parser->major > 0 && parser->minor > 0){
		if(parser->flags & F_CONNECTION_CLOSE){
			return 0;
		}
	}else{
		if(parser->flags & F_CONNECTION_KEEP_ALIVE){
			return 0;
		}
	}
	return !http_message_need_eof(parser);
}

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

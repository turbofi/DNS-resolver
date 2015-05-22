//myresolver.h by Tyler Decker
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // string operations
#include <stdint.h> // fixed width integers

const char *ipaddresses[6] = {"198.41.0.4", "192.228.79.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241"};

enum RESPONCE_CODE
{
	NOERROR = 0,
	FORMATERROR = 1,
	SERVERFAILURE = 2,
	NAMEERROR = 3,
	UNSUPPORTED = 4,
	REFUSED = 5
};
struct HEADER
{
	//following RFC 1035
	unsigned short ID; //id number
	//accounts for query, Opcode, AUTH answer, truncation, recurse(not needed), and other non needed fields

	//had to reorder these values to get valid records
	unsigned char RD :1;
	unsigned char TC :1;
	unsigned char AA :1;
	unsigned char Opcode :4;
	unsigned char QR :1;

	unsigned char RCODE :4;
	unsigned char z :3;
	unsigned char RA :1;

	unsigned short num_requests; // number of questions
	unsigned short num_answers; // number of answers
	unsigned short num_auth; // number of authorities
	unsigned short num_add; // number of resources (not needed)
};
//looking in 1035 this seems to be a good way to format this
struct QUESTION
{
	//unsigned char *name; after much issue figured out you cannot have this field
	unsigned short type;
	unsigned short class;
};
//again looking in RFC 1035 this seems a good way to structure the response
struct RDATA
{
	unsigned short TYPE;
	unsigned short CLASS;
	unsigned int TTL;
	unsigned short RDLENGTH;
};
struct RESRECORD
{
	unsigned char *name;
	struct RDATA *data_record;
	unsigned char *rdata;
};
struct RESRECORD_AAAA
{
	unsigned char *name;
	struct RDATA *data_record;
	unsigned char rdata[16];
};



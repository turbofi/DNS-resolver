// myresolver by Tyler Decker

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "myresolver.h"
//types of records
#define TYPE_A 1;
#define TYPE_AAAA 28;
#define TYPE_NS 2;
#define TYPE_CNAME 5;
#define TYPE_RRSIG 46;

//change the given hostname to correct format for DNS query (found this function online)
//very useful function found online
void nameFormatChange(unsigned char* questionname, unsigned char* hostname)
{
	int lock = 0;
	strcat((char*)hostname, ".");

	for(int i = 0; i < strlen((char *)hostname); i++)
	{
		if(hostname[i]=='.')
		{
			*questionname++ = i-lock;
			for(;lock<i;lock++)
			{
				*questionname++=hostname[lock];
			}
			lock++;
		}
	}
	*questionname++='\0';
}

//formats QUESTION message to server
void formatQuestion(struct HEADER *DNS_record, int querytype, int transaction)
{
	if(querytype == 1 || querytype == 28){
	 DNS_record -> ID = transaction;


	 DNS_record -> QR = 0;
	 DNS_record -> Opcode = 0;
	 DNS_record -> AA = 0;
	 DNS_record -> TC = 0;
	 DNS_record -> RD = 0;
	 DNS_record -> RA = 0;
	 DNS_record -> z = 0;
	 DNS_record -> RCODE = 0;
	 DNS_record -> num_requests = htons(1);
	 DNS_record -> num_answers = 0;
	 DNS_record -> num_auth = 0;
	 DNS_record -> num_add = 0;
	}
}
//Reads Record buffer also found a variation of this online
//found a method like this online
unsigned char* scanRecord(unsigned char* record, int *record_pointer, unsigned char* buffer)
{
	//acquires hostname accounts for message compression
	unsigned int offset;
	unsigned int t = 0, skipped = 0;


	unsigned char *hostname;
	//allocate hostname
	hostname = (unsigned char*)malloc(256);
	*record_pointer = 1;
	hostname[0] = '\0';

	//read in DNS domain name format
	while(*record!=0)
	{
		if(*record >= 192)
		{
			offset = (*record) * 256 + *(record+1) - 49152; // subtracting 1100000000000000
			record = buffer + offset - 1;
			skipped = 1;
		}
		else
		{
			hostname[t++] = *record; //insert DNS style host name 3www6google3com
		}
		//move forward
		record = record + 1;
		if(skipped == 0)
		{
			*record_pointer = *record_pointer + 1;
		}

	}
	hostname[t] = '\0'; //domain complete
	if(skipped == 1)
	{
		*record_pointer = *record_pointer + 1; //we can move forward
	}
	//converting host name
	int last;
	for(last = 0;last < (int)strlen((const char*)hostname); last++)
	{
		t = hostname[last];
		for(int j = 0; j < (int)t; j++)
		{
			hostname[last] = hostname[last + 1];
			last = last + 1;
		}
		hostname[last] = '.';
	}
	hostname[last - 1] = '\0';
	return hostname;

}
char * ResponceCode(enum RESPONCE_CODE code)
{
	switch(code)
	{
		case NOERROR: return "";
		case FORMATERROR: return "format error";
		case SERVERFAILURE: return "server fail";
		case NAMEERROR: return "domain name is not found returned NAMEERROR";
		case UNSUPPORTED: return "wrong query type";
		case REFUSED: return "your query was refused";
	}
	return "unknown error code";
}
//Resolver DNS function connects to DNS server and resolves host name to ip address
void printRecords( struct HEADER *DNS_record,struct RESRECORD answers[],
				   struct RESRECORD authorities[],
				   struct RESRECORD additionals[],
				   struct RESRECORD_AAAA answers_AAAA[],
				   struct RESRECORD_AAAA additionals_AAAA[])
{
	 struct sockaddr_in tell;
	 printf("\nAnswer Records : %d \n" , ntohs(DNS_record->num_answers) );
	 for(int i=0 ; i < ntohs(DNS_record->num_answers) ; i++)
	 {


	     if( ntohs(answers[i].data_record->TYPE) == 1) //IPv4 address
	     {
	    	 printf("%s ",answers[i].name);
	    	 	     printf("	%d",ntohl(answers[i].data_record->TTL));
	    	 	     printf("	%s","IN");
	         long *p;
	         p=(long*)answers[i].rdata;
	         tell.sin_addr.s_addr=(*p); //working without ntohl
	         printf("	A	%s",inet_ntoa(tell.sin_addr));
	     }
	     else if(ntohs(answers[i].data_record->TYPE)==5)
	     {
	    	 printf("%s ",answers[i].name);
	    	 	     printf("	%d",ntohl(answers[i].data_record->TTL));
	    	 	     printf("	%s","IN");
	         //Canonical name for an alias
	         printf("	CNAME	%s",answers[i].rdata);
	     }
	     else if(ntohs(answers[i].data_record->TYPE)==28)
	     {
	    	 printf("%s ",answers[i].name);
	    	 	     printf("	%d",ntohl(answers[i].data_record->TTL));
	    	 	    printf("	%s","IN");
	 	 	 printf("	AAAA	");
	 	 	 int coloncount = 0;
	 	 	 for(int j = 0; j < ntohs(answers[i].data_record->RDLENGTH); j++)
	 	 	 {
	 	 		 if(coloncount == 2)
	 	 		 {
	 	 			 printf(":");
	 	 			 if(answers_AAAA[i].rdata[j] < 10)
	 	 			 {
	 	 				 printf("%x", 0);
	 	 				 printf("%x", answers_AAAA[i].rdata[j]);
	 	 				 coloncount = 1;
	 	 			 }
	 	 			 else
	 	 			 {
	 	 				 printf("%x", answers_AAAA[i].rdata[j]);
	 	 				 coloncount = 1;
	 	 			 }

	 	 		 }
	 	 		 else
	 	 		 {
	 	 			 if(answers_AAAA[i].rdata[j] < 10)
	 	 			 {
	 	 				 printf("%x", 0);
	 	 				 printf("%x", answers_AAAA[i].rdata[j]);
	 	 				 coloncount++;
	 	 			 }
	 	 			 else
	 	 			 {
	 	 				 printf("%x", answers_AAAA[i].rdata[j]);
	 	 				 coloncount++;
	 	 			 }
	 	 		 }
	 	 	 }
	     }
	     printf("\n");
	 }

	 //print authorities
	 printf("\nAuthoritive Records : %d \n" , ntohs(DNS_record->num_auth) );
	 for(int i=0 ; i < ntohs(DNS_record->num_auth) ; i++)
	 {

    	 printf("%s ",authorities[i].name);
    	 	     printf("	%d",ntohl(authorities[i].data_record->TTL));
    	 	     printf("	%s","IN");
	     if(ntohs(authorities[i].data_record->TYPE)==2)
	     {
	         printf("	NS		%s",authorities[i].rdata);
	     }
	     printf("\n");
	 }

	 //print additional resource records
	 printf("\nAdditional Records : %d \n" , ntohs(DNS_record->num_add) );
	 for(int i=0; i < ntohs(DNS_record->num_add) ; i++)
	 {

	     if(ntohs(additionals[i].data_record->TYPE)==1)
	     {
	    	 printf("%s ",additionals[i].name);
	    	 	     printf("	%d",ntohl(additionals[i].data_record->TTL));
	    	 	     printf("	%s","IN");
	         long *p;
	         p=(long*)additionals[i].rdata;
	         tell.sin_addr.s_addr=(*p);
	         printf("	A	%s",inet_ntoa(tell.sin_addr));
	     }
	     else if(ntohs(additionals[i].data_record->TYPE)==28)
	     {
	    	 printf("%s ",additionals[i].name);
	    	 	     printf("	%d",ntohl(additionals[i].data_record->TTL));
	    	 	     printf("	%s","IN");
	 	 	 printf("	AAAA	");
	 	 	 int coloncount = 0;
	 	 	 for(int j = 0; j < ntohs(additionals[i].data_record->RDLENGTH); j++)
	 	 	 {
	 	 		 if(coloncount == 2)
	 	 		 {
	 	 			 printf(":");
	 	 			 if(additionals_AAAA[i].rdata[j] < 10)
	 	 			 {
	 	 				 printf("%x", 0);
	 	 				 printf("%x", additionals_AAAA[i].rdata[j]);
	 	 				 coloncount = 1;
	 	 			 }
	 	 			 else
	 	 			 {
	 	 				 printf("%x", additionals_AAAA[i].rdata[j]);
	 	 				 coloncount = 1;
	 	 			 }

	 	 		 }
	 	 		 else
	 	 		 {
	 	 			 if(additionals_AAAA[i].rdata[j] < 10)
	 	 			 {
	 	 				 printf("%x", 0);
	 	 				 printf("%x", additionals_AAAA[i].rdata[j]);
	 	 				 coloncount++;
	 	 			 }
	 	 			 else
	 	 			 {
	 	 				 printf("%x", additionals_AAAA[i].rdata[j]);
	 	 				 coloncount++;
	 	 			 }
	 	 		 }
	 	 	 }
	     }
	     printf("\n");
	 }


}
char* gethostfromDNS(unsigned char *hostname, char *IP_address, int querytype, unsigned short transaction, char *ipaddresses_root)
{
 //The first query is always the same either A or AAAA query type

 //keeping in mind the sie of buf, might need to change, read online that sie 65,536 is good to have
 unsigned char buf[65536], *question_name;
 struct sockaddr_in dest;
 struct HEADER *DNS_record = NULL;
 struct QUESTION *question = NULL;
 int sockfd;

//create UDP socket for DNS connection
 if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
 {
		perror("socket");
		exit(1);
 }
 dest.sin_family = AF_INET;
 dest.sin_port = htons(53); //RFC 1035 dictates that DNS uses port 53 for UDP
 dest.sin_addr.s_addr = inet_addr(IP_address);

 //format DNS record for DNS server (flags) in QUESTION
 DNS_record = (struct HEADER *)&buf;
 formatQuestion(DNS_record, querytype, transaction);
 //intialie question_name to store correct formated host name example "3www6google3com"
 question_name =(unsigned char*)&buf[sizeof(struct HEADER)];
 nameFormatChange(question_name, hostname);
 //intialie question into correct format with question_name
 question = (struct QUESTION*)&buf[sizeof(struct HEADER) + (strlen((const char*)question_name)+1)];
//set the type and class usually for sending A AAAA only
 question -> type = htons(querytype);
 question -> class = htons(1);
 //set timeout of recvfrom to 500 ms seems to be a safe bet
 struct timeval tv;
 tv.tv_sec = 0;
 tv.tv_usec = 500000;
 if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
     perror("Error");
 }
//send request to DNS server, will try to resend three times then move on
 bool valid_recieve = false;
 int num_resend = 0;
 while(!valid_recieve)
 {
  if(num_resend == 4)
  {
	    printf("Too many connection timeouts will try next available server...");
	    close(sockfd);
	    return NULL;
  }
  if( sendto(sockfd,(char*)buf,sizeof(struct HEADER) + (strlen((const char*)question_name)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
  {
        printf("sending failed, will try again");
        num_resend++;
        continue;
  }
  int dest_size = sizeof(dest);
  //get answer from DNS server
  int bufRecvSie = recvfrom ( sockfd,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&dest_size );
  if(bufRecvSie < 0)
     {
	    printf("Timout reached. Resending segment %d\n", transaction);
	    num_resend++;
     }
  else if (bufRecvSie < sizeof(struct RESRECORD))
 	 {
	 	printf("bad packet from server\n");
 	 }
  else
  	 {
	  	valid_recieve = true;
  	 }
 }

 //format in correct buffer
 DNS_record = (struct HEADER*) buf;
 //get correct starting position to read from buffer
 unsigned char* fromDNS = &buf[sizeof(struct HEADER) + (strlen((const char*)question_name)+1) + sizeof(struct QUESTION)];

 //check if there is an error code associated with response
 if(DNS_record -> RCODE != 0)
 {
     fputs(ResponceCode(DNS_record -> RCODE),stderr);
     return NULL;
 }
 //points to position in buffer
 int buffer_point = 0;
 //create RES records im pretty sure i remember 20 is the max from somewhere
 struct RESRECORD answers[20];
 struct RESRECORD authorities[20];
 struct RESRECORD additionals[20];
 struct RESRECORD_AAAA answers_AAAA[20];
 struct RESRECORD_AAAA additionals_AAAA[20];

 //Acquire answers if any from the response
 for(int i = 0;i < ntohs(DNS_record->num_answers);i++)
 {
	 //get the name
	 answers[i].name = scanRecord(fromDNS, &buffer_point, buf);
	 //move the buf from server forward
	 fromDNS += buffer_point;
	 //now time to insert data record
	 answers[i].data_record = (struct RDATA*)(fromDNS);
	 //move forward in the fromDNS buffer
	 fromDNS += sizeof(struct RDATA) - 2;
	 //now for every answer's data
	 //check if IPV4 address
	 if(ntohs(answers[i].data_record->TYPE) == 1)
	 {
		 answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].data_record->RDLENGTH));

	 	 for(int j = 0; j < ntohs(answers[i].data_record->RDLENGTH); j++)
	 	 {
	 		 answers[i].rdata[j] = fromDNS[j]; //inserting data record into answer
	 	 }
	 	 answers[i].rdata[ntohs(answers[i].data_record->RDLENGTH)] = '\0';
	 	 //move fromDNS buffer forward
	 	 fromDNS += ntohs(answers[i].data_record->RDLENGTH);
	 }
	 else if(ntohs(answers[i].data_record->TYPE) == 28)
	 {
		 // for test //int datalength = ntohs(additionals[i].data_record->RDLENGTH);
		 answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].data_record->RDLENGTH));
		 unsigned char r_data[16];
	 	 for(int j = 0; j < ntohs(answers[i].data_record->RDLENGTH); j++)
	 	 {
	 		 r_data[j] = *fromDNS; //inserting data record into answer
	 		 answers_AAAA[i].rdata[j] = *fromDNS;
	 		 fromDNS += 1; //move fromDNS buffer forward
	 	 }


	 	answers[i].rdata = r_data;

	 }
	 else
	 {
		 answers[i].rdata = scanRecord(fromDNS, &buffer_point, buf);
		 fromDNS += buffer_point;
	 }
 }
 //Acquire authorities if any form the response
 for(int i = 0; i < ntohs(DNS_record->num_auth); i++)
 {
	 authorities[i].name = scanRecord(fromDNS, &buffer_point, buf);
	 fromDNS += buffer_point;

		 authorities[i].data_record = (struct RDATA*)(fromDNS);
		 fromDNS += sizeof(struct RDATA) - 2;

	 authorities[i].rdata = scanRecord(fromDNS, &buffer_point, buf);
	 fromDNS += buffer_point;
 }
 //Acquire additionals if any from the response
 for(int i = 0;i < ntohs(DNS_record->num_add);i++)
 {
	 additionals[i].name = scanRecord(fromDNS, &buffer_point, buf);
	 //move the buf from server forward
	 fromDNS += buffer_point;
	 //now time to insert data record
	 additionals[i].data_record = (struct RDATA*) fromDNS;
	 fromDNS += sizeof(struct RDATA) - 2;
	 //now for every additionals's data
	 if(ntohs(additionals[i].data_record->TYPE) == 1)
	 {
		 //unsigned int datalength = ntohs(additionals[i].data_record->RDLENGTH);
		 additionals[i].rdata = (unsigned char*)malloc(ntohs(additionals[i].data_record->RDLENGTH));
	 	 for(int j = 0; j < ntohs(additionals[i].data_record->RDLENGTH); j++)
	 	 {
	 		 additionals[i].rdata[j] = fromDNS[j]; //inserting data record into answer
	 	 }
	 	 additionals[i].rdata[ntohs(additionals[i].data_record->RDLENGTH)] = '\0';
	 	 //move fromDNS buffer forward
	 	 fromDNS += ntohs(additionals[i].data_record->RDLENGTH);
	 }
	 else if(ntohs(additionals[i].data_record->TYPE) == 28)
	 {
		 // for test //int datalength = ntohs(additionals[i].data_record->RDLENGTH);
		 additionals[i].rdata = (unsigned char*)malloc(ntohs(additionals[i].data_record->RDLENGTH));
		 unsigned char r_data[16];
	 	 for(int j = 0; j < ntohs(additionals[i].data_record->RDLENGTH); j++)
	 	 {
	 		 r_data[j] = *fromDNS; //inserting data record into answer
	 		 additionals_AAAA[i].rdata[j] = *fromDNS;
	 		 fromDNS += 1; //move fromDNS buffer forward
	 	 }



	 	additionals[i].rdata = r_data;

	 }
	 else
	 {
		 additionals[i].rdata = scanRecord(fromDNS, &buffer_point, buf);
		 fromDNS += buffer_point;
	 }
 }
 //now check for answer if we have A (default) or AAAA when queried one then we are done
 /*
  * FOR TEST REMEMBER TO DELETE
  */
 //printRecords(DNS_record, answers, authorities, additionals, answers_AAAA, additionals_AAAA);
 /*
  * REMEMBER TO DELETE
  */
 //If we have an answer then it leads to CNAME chase or actual answer

 if(ntohs(DNS_record->num_answers) > 0)
 {
	 //go through each of the answer records
	 for(int i = 0; i < ntohs(DNS_record->num_answers); i++)
	 {
		 //if equal to CNAME
	     if(ntohs(answers[i].data_record->TYPE)==5)
	     {
	    	 //print out the CNAME record for console
	    	 printf("%s ",answers[i].name);
	    	 	     printf("	%d",ntohl(answers[i].data_record->TTL));
	    	 	     printf("	%s","IN");
	         //Canonical name for an alias
	         printf("	CNAME	%s\n",answers[i].rdata);
	         //check just in case all 6 of root servers

	          char *returnedIP = gethostfromDNS(answers[i].rdata, ipaddresses_root, querytype, transaction+1, ipaddresses_root);
	          //if one is returned successfully then we can return from function
	          if(returnedIP)
	          {
	        	  if(strcmp(returnedIP, "CNAMECHECKED") == 0)
	        	  	{
	     	         //warn about CNAME assumption could DELETE
	        		  if(querytype == 28)
	        		  {
	 	     	         printf("CNAME	%s could not be resolved to AAAA\n",answers[i].rdata);
	 	     	         printf("If other CNAME's are available, will try to resolve..\n");
	        		  }
	        		  else if(querytype == 1)
	        		  {
	        			 printf("CNAME	%s could not be resolved to A\n",answers[i].rdata);
	        			 printf("If other CNAME's are available, will try to resolve..\n");
	        		  }
	     	         //
	        	  	}
	        	 close(sockfd);
	        	 return returnedIP;
	          }

	     }
	 }
	 bool found_answer = false;
	 struct sockaddr_in tell;
	 //now check for actual answers if there is no CNAME to chase
	 for(int i = 0; i < ntohs(DNS_record->num_answers); i++)
	 {
		 // if A record IPV4
	     if(ntohs(answers[i].data_record->TYPE)==1)
	     {
	    	 found_answer = true;
	    	 printf("%s ",answers[i].name);
	    	 	     printf("	%d",ntohl(answers[i].data_record->TTL));
	    	 	     printf("	%s","IN");
	         //Canonical name for an alias
	    	 long *p;
	    	 p=(long*)answers[i].rdata;
	    	 tell.sin_addr.s_addr=(*p); //working without ntohl
	    	 printf("	A	%s\n",inet_ntoa(tell.sin_addr));
	     }
	     // if AAAA record IPV6
	     else if(ntohs(answers[i].data_record->TYPE)==28)
	     {
	    	 found_answer = true;
	    	 printf("%s ",answers[i].name);
	    	 	     printf("	%d",ntohl(answers[i].data_record->TTL));
	    	 	    printf("	%s","IN");
	 	 	 printf("	AAAA	");
	 	 	 int coloncount = 0;
	 	 	 for(int j = 0; j < ntohs(answers[i].data_record->RDLENGTH); j++)
	 	 	 {
	 	 		 if(coloncount == 2)
	 	 		 {
	 	 			 printf(":");
	 	 			 if(answers_AAAA[i].rdata[j] < 10)
	 	 			 {
	 	 				 printf("%x", 0);
	 	 				 printf("%x", answers_AAAA[i].rdata[j]);
	 	 				 coloncount = 1;
	 	 			 }
	 	 			 else
	 	 			 {
	 	 				 printf("%x", answers_AAAA[i].rdata[j]);
	 	 				 coloncount = 1;
	 	 			 }

	 	 		 }
	 	 		 else
	 	 		 {
	 	 			 if(answers_AAAA[i].rdata[j] < 10)
	 	 			 {
	 	 				 printf("%x", 0);
	 	 				 printf("%x", answers_AAAA[i].rdata[j]);
	 	 				 coloncount++;
	 	 			 }
	 	 			 else
	 	 			 {
	 	 				 printf("%x", answers_AAAA[i].rdata[j]);
	 	 				 coloncount++;
	 	 			 }
	 	 		 }
	 	 	 }
	 	 	 printf("\n");
	     }
	     // base case have to return we have an actual answer
	     if(found_answer && i == (ntohs(DNS_record->num_answers) - 1))
	     {
	     	close(sockfd);
	     	return inet_ntoa(tell.sin_addr);
	     }
	 }
	 close(sockfd);
	 return NULL;
 }
 //check for an authority that might know where to go
 else if(ntohs(DNS_record->num_auth) > 0)
 {
	 struct sockaddr_in tell;
	 //for each authority just in case we have to chase through each one
	 for(int i = 0; i < ntohs(DNS_record->num_auth); i++)
	 {
		 //if there is an additional that may tell me where authority is located
		 if(ntohs(DNS_record->num_add) > 0)
		 {
			 //loop through each additional record
			 bool checked_auth = false;
			 for(int j = 0; j < ntohs(DNS_record->num_add); j++)
			 {
				 if(checked_auth) break; //if record auth at i was checked then just continue onto next i
				 //if record points to a name server NS to go to
			     if(ntohs(authorities[i].data_record->TYPE)==2)
			     {
			    	 //if the additional in the record starting out at first has IP address
				     if(ntohs(additionals[j].data_record->TYPE)==1)
				     {
				    	 //if additional tells IPV4 address of authority nameserver
				 	 	 if(strcmp(authorities[i].rdata, additionals[j].name) == 0)
				 	 	 {
					         long *p;
					         p=(long*)additionals[j].rdata;
					         tell.sin_addr.s_addr=(*p);

					         // return the IP address from asking nameserver gives us answer where hostname is
					          hostname[strlen((char*)hostname) - 1] = '\0';
					          char *returnedIP = gethostfromDNS(hostname, inet_ntoa(tell.sin_addr), querytype, transaction+1, ipaddresses_root);

					          if(returnedIP)
					          {

						        	 close(sockfd);
						        	 return returnedIP;
					          }
					          checked_auth = true;
				 	 	 }
				     }		//
				 }
			 }
		 }
		 //there is no additional must now chase nameserver name from authority to find it's IP address
		 else
		 {
			 for(int j = 0; j < ntohs(DNS_record->num_auth); j++)
			 {
			     if(ntohs(authorities[j].data_record->TYPE)==2)
				 {
			    	 //returnedIP now holds IP of a nameserver
			    	 char *returnedIP = gethostfromDNS(authorities[j].rdata, ipaddresses_root, querytype, transaction+1, ipaddresses_root);
			         if(returnedIP)
			         {
			        	  //ask name server for IP of name in question
			        	  char *hostIP = gethostfromDNS(hostname, returnedIP, querytype, transaction+2, ipaddresses_root);
				          if(hostIP)
				          {
				        	 close(sockfd);
				        	 return hostIP;
				          }
			         }
			     }
			     else
			     {

			     }
			  }
			 close(sockfd);
			 return "CNAMECHECKED";

		  }

	 }
 }

 close(sockfd);
 return NULL;
}

//main function
int main(int argc, char *argv[])
{
    unsigned char *hostname;
    int query_type;
    // check to see how many arguments
    if (argc == 1)
    {
        fputs("Need at least a URL argument for myresolver!\n",stderr);
        exit(1);
    }
    else if (argc == 2)
    {
        hostname = argv[1];
        query_type = TYPE_A; //default
    }
    else if (argc == 3)
    {
        hostname = argv[1];
        if(strcmp(argv[2], "A") == 0){
            query_type = TYPE_A;
        }
        else if(strcmp(argv[2], "AAAA") == 0){
            query_type = TYPE_AAAA;
        }
        else{
            fputs("Need valid address type (A, AAAA) \n",stderr);
            exit(1);
        }
    }
    else{
        fputs("Wrong number of arguments! (host name, <optional> address type (A, AAAA) )\n",stderr);
        exit(1);
    }

    unsigned short transaction = 1;
    //main resolve function call, more will be made inside the function
    //************REMEMBER TO REINSTATE********************************
    for(int i = 0; i < 6; i++)
    {
    	char *returnedIP = gethostfromDNS(hostname, ipaddresses[i], query_type, transaction, ipaddresses[i]);
    		          //if one is returned successfully then we can return from function
    		          if(returnedIP)
    		          {
    		        	  if(strcmp(returnedIP, "CNAMECHECKED") == 0)
    		        	  	{
    		        		  printf("could not resolve domain name\n");
    		        	  	}
    		        	 break;
    		          }
    }
    return 0;
}

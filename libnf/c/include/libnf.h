/*! \file libnf.h
	\brief libnf C interface
    The libnf.h is complete public application interface for accessing all 
	libnf functions. The API is divided into several section where each section 
	represents specific operation for file, record, filter, in memory aggregation.

	For examples how to use library please visit examples directory in the root of 
	source files. 
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* uncommon types used by libnf */
/* IP address, MAC address, MPLS stack */
//typedef struct in6_addr lnf_ip_t;
typedef struct lnf_ip_s { uint32_t data[4]; } lnf_ip_t;
typedef struct lnf_mac_s { uint8_t data[6]; }  lnf_mac_t;
typedef struct lnf_mpls_s { uint32_t data[10]; } lnf_mpls_t;

/* basic record type 1 - contains the most commonly used fields */
typedef struct lnf_brec1_s {
	uint64_t	first;			/* LNF_FLD_FIRST */
	uint64_t	last;			/* LNF_FLD_LAST */
	lnf_ip_t	srcaddr;		/* LNF_FLD_SRCADDR */
	lnf_ip_t	dstaddr;		/* LNF_FLD_DSTADDR */
	uint8_t		prot;			/* LNF_FLD_PROT */
	uint16_t	srcport;		/* LNF_FLD_SRCPORT */
	uint16_t	dstport;		/* LNF_FLD_DSTPORT */
	uint64_t	bytes;			/* LNF_FLD_DOCTETS */
	uint64_t	pkts;			/* LNF_FLD_DPKTS */
	uint64_t	flows;			/* LNF_FLD_AGGR_FLOWS */
} lnf_brec1_t;

#define LNF_MAX_STRING		512

/* type of fields */
/* note: if the fields type allows two kind of data type  */
/* for example UINT32 and UINT64 libnf always uses the biggest one */
#define LNF_NONE			0x00
#define LNF_UINT8			0x08
#define LNF_UINT16			0x16
#define LNF_UINT32			0x32
#define LNF_UINT64			0x64
#define LNF_DOUBLE			0x70
#define LNF_ADDR 			0xA1	/* 128 bit addr (struct in6_addr/network order) */
#define LNF_MAC				0xA2
#define LNF_STRING			0xAA	/* null terminated string */
#define LNF_MPLS			0xAB	/* mpls labels */
#define LNF_BASIC_RECORD1	0xB1


#define LNF_MASK_TYPE  		0x0000FF
#define LNF_MASK_FIELD 		0xFFFF00 

#define LNF_GET_TYPE(x) 	(x & LNF_MASK_TYPE)
//#define LNF_GET_FIELD(x) 	((x & LNF_MASK_FIELD) >> 8)
#define LNF_GET_FIELD(x) 	x

/* top two bytes of field identifies data type LNF_UINT8, ... */
/* 01 - 9F - ordinary fields */
/* A0 - DF - extra fields - computed etc. */
/* EF - FF - reserved */
#define LNF_FLD_ZERO_			0x00
#define LNF_FLD_FIRST			0x01 
#define LNF_FLD_LAST			0x02 
#define LNF_FLD_RECEIVED		0x03 
#define LNF_FLD_DOCTETS			0x04 
#define LNF_FLD_DPKTS			0x05 
#define LNF_FLD_OUT_BYTES		0x06 
#define LNF_FLD_OUT_PKTS		0x07 
#define LNF_FLD_AGGR_FLOWS		0x08 
#define LNF_FLD_SRCPORT 		0x09 
#define LNF_FLD_DSTPORT			0x0a 
#define LNF_FLD_TCP_FLAGS		0x0b 
#define LNF_FLD_SRCADDR 		0x0c 
#define LNF_FLD_DSTADDR			0x0d 
#define LNF_FLD_IP_NEXTHOP		0x0e 
#define LNF_FLD_SRC_MASK		0x0f 
#define LNF_FLD_DST_MASK		0x10 
#define LNF_FLD_TOS				0x11 
#define LNF_FLD_DST_TOS			0x12 
#define LNF_FLD_SRCAS			0x13 
#define LNF_FLD_DSTAS			0x14 
#define LNF_FLD_BGPNEXTADJACENTAS	0x15 
#define LNF_FLD_BGPPREVADJACENTAS	0x16 
#define LNF_FLD_BGP_NEXTHOP			0x17 
#define LNF_FLD_PROT	 		0x18
#define LNF_FLD_SRC_VLAN		0x19
#define LNF_FLD_DST_VLAN		0x1a
#define LNF_FLD_IN_SRC_MAC		0x1b
#define LNF_FLD_OUT_SRC_MAC		0x1c
#define LNF_FLD_IN_DST_MAC		0x1d
#define LNF_FLD_OUT_DST_MAC		0x1e
#define LNF_FLD_MPLS_LABEL		0x1f
#define LNF_FLD_INPUT			0x20
#define LNF_FLD_OUTPUT			0x21
#define LNF_FLD_DIR				0x22
#define LNF_FLD_FWD_STATUS		0x23
#define LNF_FLD_IP_ROUTER		0x24
#define LNF_FLD_ENGINE_TYPE		0x25
#define LNF_FLD_ENGINE_ID		0x26
#define LNF_FLD_EVENT_TIME		0x27
#define LNF_FLD_CONN_ID			0x28
#define LNF_FLD_ICMP_CODE		0x29
#define LNF_FLD_ICMP_TYPE		0x2a
#define LNF_FLD_FW_XEVENT		0x2b
#define LNF_FLD_XLATE_SRC_IP	0x2c
#define LNF_FLD_XLATE_DST_IP	0x2d
#define LNF_FLD_XLATE_SRC_PORT	0x2e
#define LNF_FLD_XLATE_DST_PORT	0x2f
#define LNF_FLD_INGRESS_ACL_ID	0x30
#define LNF_FLD_INGRESS_ACE_ID	0x31
#define LNF_FLD_INGRESS_XACE_ID	0x32
#define LNF_FLD_EGRESS_ACL_ID	0x33
#define LNF_FLD_EGRESS_ACE_ID	0x34
#define LNF_FLD_EGRESS_XACE_ID	0x35
#define LNF_FLD_USERNAME		0x36
#define LNF_FLD_INGRESS_VRFID	0x37
#define LNF_FLD_EVENT_FLAG		0x38
#define LNF_FLD_EGRESS_VRFID	0x39
#define LNF_FLD_BLOCK_START		0x3a
#define LNF_FLD_BLOCK_END		0x3b
#define LNF_FLD_BLOCK_STEP		0x3c
#define LNF_FLD_BLOCK_SIZE		0x3d
#define LNF_FLD_CLIENT_NW_DELAY_USEC	0x3e 
#define LNF_FLD_SERVER_NW_DELAY_USEC	0x3f 
#define LNF_FLD_APPL_LATENCY_USEC		0x40 

/* compudted and extra fields */
#define LNF_FLD_CALC_DURATION	 0xA0 			/* computed : duration in msec  */
#define LNF_FLD_CALC_BPS		 0xA1 			/* computed : Bytes per second  */
#define LNF_FLD_CALC_PPS		 0xA2 			/* computed : packets per second  */
#define LNF_FLD_CALC_BPP		 0xA3 			/* computed : bytes per packet */
#define LNF_FLD_BREC1			 0xB0 			/* special field for lnf_brec1_t */

#define LNF_FLD_TERM_			 0xFF  			/* ID of last field */

/* text description of fields */
typedef struct lnf_field_s {
	int index;			/*!< numerical index of field */
	int default_aggr;	/*!< default aggregation function */
	int default_sort;	/*!< default sort order */
	char *name;			/**< field name */
	char *fld_descr;	/**< short description */
} lnf_field_t;


#ifndef _HAVE_LIBNF_STRUCT_H_ 
/* dummy portable handles - the comlete definition is */
/* available at libnf_struct.h in lnf sources */
typedef void lnf_file_t;	
typedef void lnf_rec_t;		
typedef void lnf_filter_t;
typedef void lnf_mem_t;
#endif

 
#define LNF_OK				0x0001	/* OK status */
#define LNF_EOF 			0x0000	/* end of file */

#define LNF_ERR_UNKBLOCK	-0x0001	/* weak error: unknown block type */
#define LNF_ERR_UNKREC		-0x0002	/* weak error: unknown record type */
#define LNF_ERR_COMPAT15	-0x0004	/* weak error: old blok type suppoerted by nfdump 1.5 */
#define LNF_ERR_WEAK		-0x000F	/* all weak errors (errors to skip) */

#define LNF_ERR_READ		-0x0010	/* read error (IO) */
#define LNF_ERR_CORRUPT		-0x0020	/* coruprted file */
#define LNF_ERR_EXTMAPB		-0x0040	/* too big extension map */
#define LNF_ERR_EXTMAPM		-0x0080	/* missing extension map */
#define LNF_ERR_WRITE		-0x00F0	/* write error */

#define LNF_ERR_NOTSET		-0x0100	/* item is not set  */
#define LNF_ERR_UNKFLD		-0x0200	/* unknown field  */
#define LNF_ERR_FILTER		-0x0400	/* cannot compile filter  */
#define LNF_ERR_NOMEM		-0x0800	/* cannot allocate memory  */
#define LNF_ERR_OTHER		-0x0F00	/* some other error */


/* flags for file open */
#define LNF_READ	0x0		/* open file for reading */
#define LNF_WRITE	0x1		/* open file for for writing */
#define LNF_ANON	0x2		/* set anon flag on the file */
#define LNF_COMP	0x4		/* the file is compressed */
#define LNF_WEAKERR	0x8		/* return weak erros $(unknow block, record) */


/* constants for lnf_info function */
#define LNF_INFO_VERSION		0x02	/* string with lbnf version - char* */
#define LNF_INFO_NFDUMP_VERSION	0x04	/* string with nfdump version that libnf is based on - char**/
#define LNF_INFO_FILE_VERSION	0x06	/* nfdump file version  - int*/
#define LNF_INFO_BLOCKS			0x08	/* number of block in file - unit64_t */
#define LNF_INFO_COMPRESSED		0x0A	/* is file compressed - int */
#define LNF_INFO_ANONYMIZED		0x0C	/* is file anonymized - int */
#define LNF_INFO_CATALOG		0x0E	/* file have catalog - int */
#define LNF_INFO_IDENT			0x10	/* string ident - char* */
#define LNF_INFO_FIRST			0x12	/* msec of first packet in file - unit64_t */
#define LNF_INFO_LAST			0x14	/* msec of last packet in file - uint64_t */
#define LNF_INFO_FAILURES		0x16	/* number of sequence failures - uint64_t */
#define LNF_INFO_FLOWS			0x18	/* summary of stored flows - uint64_t */
#define LNF_INFO_BYTES			0x1A	/* summary of stored bytes - uint64_t */
#define LNF_INFO_PACKETS		0x1C	/* summary of stored packets - uint64_t */
#define LNF_INFO_PROC_BLOCKS	0x1E	/* number of processed blocks - uint64_t */


/*! 
	\defgroup file Basic file operations (red/create/write)
	\defgroup record  Record operations, fields extraction
	\defgroup filter  Filter operations
	\defgroup memheap In memmory aggregation and sorting module
	\defgroup error Error handling 
*/

/*! 
	\ingroup error 

	\brief return error string of last error 
	\param buffer where the message will be copied 
	\param available space in buffer 
*/
void lnf_error(const char *buf, int buflen);

/****************************************************
* file module                                       *
*****************************************************/

/*! 
	\ingroup file 

	This module provides basic operation on file. The file can 
	be open in either read or write mode. In write mode the 
	new one is created or if the file exists then is ovewritten. 
*/

/*! \ingroup file 

\brief initialise lnf_filep structure and opens file for read/write 

The lnf_read/lnf_write operations works with record strcuture (see record operations)

\param **lnf_filep 	pointer to lnf_filep_t structure 
\param *filename 	path and file to open 
\param flags 		flags 
\param *ident 		file ident for newly created files, can be set to NULL
\return 			LNF_OK, LNF_ERR_NOMEM 
*/
int lnf_open(lnf_file_t **lnf_filep, const char *filename, unsigned int flags, const char *ident);


/*!	\ingroup file 
\brief 	Read next record from file 

Read nex record from file. The record is stored in lnf_rec object. 

\param *lnf_file 	pointer to lnf_filep_t structure 
\param *lnf_rec 	pointer to initialised record structure 
\return 			LNF_OK, LNF_ERR_NOMEM 
*/
int lnf_read(lnf_file_t *lnf_file, lnf_rec_t *lnf_rec);
int lnf_write(lnf_file_t *lnf_file, lnf_rec_t *lnf_rec);
int lnf_info(lnf_file_t *lnf_file, int info, void *data, size_t size);
void lnf_close(lnf_file_t *lnf_file);


/* record operations */
int lnf_rec_init(lnf_rec_t **recp);
void lnf_rec_clear(lnf_rec_t *rec);
int lnf_rec_copy(lnf_rec_t *dst, lnf_rec_t *src);
int lnf_rec_fset(lnf_rec_t *rec, int field, void *data);
int lnf_rec_fget(lnf_rec_t *rec, int field, void *data);
void lnf_rec_free(lnf_rec_t *rec);


/* filter operations */
int	lnf_filter_init(lnf_filter_t **filterp, char *expr);
int	lnf_filter_match(lnf_filter_t *filter, lnf_rec_t *rec);
void lnf_filter_free(lnf_filter_t *filter);

#define LNF_MAX_THREADS 128		/* maximum threads */

/* memory heap operations */
int lnf_mem_init(lnf_mem_t **lnf_mem);

/* flags for lnf_mem_addf */
#define LNF_AGGR_KEY	0x0000	/* the key item */
#define LNF_AGGR_MIN	0x0001	/* min value - for LNF_FLD_FIRST */
#define LNF_AGGR_MAX	0x0002	/* max value - for LNF_FLD_LAST */
#define LNF_AGGR_SUM	0x0003	/* summary of values - for all counters */
#define LNF_AGGR_OR		0x0004	/* OR operation - for LNF_TCP_FLAGS */
#define LNF_AGGR_FLAGS	0x000F

#define LNF_SORT_NONE	0x0000	/* do not sort by this field */
#define LNF_SORT_ASC	0x0010	/* sort by item ascending */
#define LNF_SORT_DESC	0x0020	/* sort by item descending */
#define LNF_SORT_FLAGS	0x00F0

int lnf_mem_fadd(lnf_mem_t *lnf_mem, int field, int flags, int numbits, int numbits6);

#define LNF_FAST_AGGR_NONE	0x0000	/* do not set fast aggregation mode */
#define LNF_FAST_AGGR_BASIC	0x0001	/* perform aggregation on items FIRST,LAST,BYTES,PKTS */
#define LNF_FAST_AGGR_ALL	0x0002	/* aggregation on all items */

int lnf_mem_fastaggr(lnf_mem_t *lnf_mem, int flags);

int lnf_mem_write(lnf_mem_t *lnf_mem, lnf_rec_t *rec);
int lnf_mem_merge_threads(lnf_mem_t *lnf_mem);
int lnf_mem_read(lnf_mem_t *lnf_mem, lnf_rec_t *rec);
void lnf_mem_free(lnf_mem_t *lnf_mem);


/* fields management */
int lnf_fld_type(int field);
#define LNF_FLD_INFO_FIELDS	0x01	/* fill array of ints ended with LNF_FLD_TERM_  */
#define LNF_FLD_INFO_TYPE	0x02	/* type - int */
#define LNF_FLD_INFO_NAME	0x04	/* name - char* */
#define LNF_FLD_INFO_DESCR	0x08	/* description - char * */
#define LNF_FLD_INFO_AGGR	0x0B	/* default aggregation - int */
#define LNF_FLD_INFO_SORT	0x0E	/* default sort - int */

#define LNF_INFO_BUFSIZE 4096		/* maximum buffer size for data lnf_*_fields */
/* return LNF_OK or LNF_ERR_UNKFLD or LNF_ERR_OTHER */
int lnf_fld_info(int field, int info, void *data, size_t size);
int lnf_fld_parse(char *str, int *numbits, int *numbits6);


#ifndef IN6_IS_ADDR_V4COMPAT
#define IN6_IS_ADDR_V4COMPAT(a) \
   ((((uint32_t *) (a))[0] == 0) && (((uint32_t *) (a))[1] == 0) && \
   (((uint32_t *) (a))[2] == 0) && (ntohl (((uint32_t *) (a))[3]) > 1))
#endif



/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 *  $Author: haag $
 *
 *  $Id: nftree.h 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 */

#ifndef _NFTREE_H
#define _NFTREE_H 1

/*
 * type definitions for nf tree
 */
#include <netinet/in.h>

#include <byteswap.h>
#include <endian.h>
#include <stdint.h>

#ifdef __CHECKER__
#define __bitwise __attribute__((bitwise))
#define __force __attribute__((force))
#else
#define __bitwise
#define __force
#endif

typedef uint16_t __bitwise le16_t;
typedef uint16_t __bitwise be16_t;
typedef uint32_t __bitwise le32_t;
typedef uint32_t __bitwise be32_t;
typedef uint64_t __bitwise le64_t;
typedef uint64_t __bitwise be64_t;

#undef htobe16
#undef htole16
#undef be16toh
#undef le16toh
#undef htobe32
#undef htole32
#undef be32toh
#undef le32toh
#undef htobe64
#undef htole64
#undef be64toh
#undef le64toh

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define bswap_16_on_le(x) __bswap_16(x)
#define bswap_32_on_le(x) __bswap_32(x)
#define bswap_64_on_le(x) __bswap_64(x)
#define bswap_16_on_be(x) (x)
#define bswap_32_on_be(x) (x)
#define bswap_64_on_be(x) (x)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define bswap_16_on_le(x) (x)
#define bswap_32_on_le(x) (x)
#define bswap_64_on_le(x) (x)
#define bswap_16_on_be(x) __bswap_16(x)
#define bswap_32_on_be(x) __bswap_32(x)
#define bswap_64_on_be(x) __bswap_64(x)
#endif

static inline le16_t htole16(uint16_t value) { return (le16_t __force) bswap_16_on_be(value); }
static inline le32_t htole32(uint32_t value) { return (le32_t __force) bswap_32_on_be(value); }
static inline le64_t htole64(uint64_t value) { return (le64_t __force) bswap_64_on_be(value); }

static inline be16_t htobe16(uint16_t value) { return (be16_t __force) bswap_16_on_le(value); }
static inline be32_t htobe32(uint32_t value) { return (be32_t __force) bswap_32_on_le(value); }
static inline be64_t htobe64(uint64_t value) { return (be64_t __force) bswap_64_on_le(value); }

static inline uint16_t le16toh(le16_t value) { return bswap_16_on_be((uint16_t __force)value); }
static inline uint32_t le32toh(le32_t value) { return bswap_32_on_be((uint32_t __force)value); }
static inline uint64_t le64toh(le64_t value) { return bswap_64_on_be((uint64_t __force)value); }

static inline uint16_t be16toh(be16_t value) { return bswap_16_on_le((uint16_t __force)value); }
static inline uint32_t be32toh(be32_t value) { return bswap_32_on_le((uint32_t __force)value); }
static inline uint64_t be64toh(be64_t value) { return bswap_64_on_le((uint64_t __force)value); }

enum BlockValueType {
        UINT64,
        LNF_IP,
        _BLOCK_DATA_TYPE_MAX,
        _BLOCK_DATA_TYPE_INVALID,
};

typedef struct BlockValue_s {
        int type;
        union {
                uint64_t data;
                struct in6_addr addr;
                uint64_t _addr[2];
        };
        union {
                struct in6_addr mask;
                uint64_t _m[2];
        };
} BlockValue;

typedef enum {
        BASIC_BLOCK,
        LNF_BLOCK,
} BlockType;

#define VAL_NUM(x) (BlockValue) {.type = UINT64, .data = x, ._m = {0xffffffffffffffffULL, 0xffffffffffffffffULL}}
#define VAL_IP(x) (BlockValue) {.type = LNF_IP, .addr = x, ._m = {0xffffffffffffffffULL, 0xffffffffffffffffULL}}
#define VAL_IP_MASK(x, y) (BlockValue) {.type = LNF_IP, .addr = x , ._m[0] = htobe64(y[0]), ._m[1] = htobe64(y[1])}

typedef void (*flow_proc_t)(uint64_t *, uint64_t *);
typedef void (*flow_lnf_proc_t)(void *r, BlockValue *v, BlockValue *v1);

typedef struct FilterBlock {
	/* Filter specific data */
	uint32_t	offset;
	uint64_t	mask;
	uint64_t	value;

        BlockValue      value1;
        BlockType       type;

	/* Internal block info for tree setup */
	uint32_t	superblock;			/* Index of superblock */
	uint32_t	*blocklist;			/* index array of blocks, belonging to
								   	   this superblock */
	uint32_t	numblocks;			/* number of blocks in blocklist */
	uint32_t	OnTrue, OnFalse;	/* Jump Index for tree */
	int16_t		invert;				/* Invert result of test */
	uint16_t	comp;				/* comperator */
	flow_proc_t	function;			/* function for flow processing */
        flow_lnf_proc_t function1;
	char		*fname;				/* ascii function name */
	void		*data;				/* any additional data for this block */
        
        uint16_t field;
} FilterBlock_t;

typedef struct FilterEngine_data_s {
	FilterBlock_t	*filter;
	uint32_t		StartNode;
	uint32_t 		Extended;
	char			**IdentList;
	uint64_t		*nfrecord;
        void* lnf_rec;
	int (*FilterEngine)(struct FilterEngine_data_s *);
} FilterEngine_data_t;


/* 
 * Definitions
 */
enum { CMP_EQ = 0, CMP_GT, CMP_LT, CMP_IDENT, CMP_FLAGS, CMP_IPLIST, CMP_ULLIST };

/*
 * filter functions:
 * For some filter functions, netflow records need to be processed first in order to filter them
 * This involves all data not directly available in the netflow record, such as packets per second etc. 
 * Filter speed is a bit slower due to extra netflow processsing
 * The sequence of the enum values must correspond with the entries in the flow_procs array
 */

enum { 	FUNC_NONE = 0,	/* no function - just plain filtering - just to be complete here */
		FUNC_PPS,		/* function code for pps ( packet per second ) filter function */
		FUNC_BPS,		/* function code for bps ( bits per second ) filter function */
		FUNC_BPP,		/* function code for bpp ( bytes per packet ) filter function */
		FUNC_DURATION,	/* function code for duration ( in miliseconds ) filter function */
		FUNC_MPLS_EOS,	/* function code for matching End of MPLS Stack label */
		FUNC_MPLS_ANY,	/* function code for matching any MPLS label */ 
		FUNC_PBLOCK		/* function code for matching ports against pblock start */
};

/* 
 * Tree type defs
 */

/* Definition of the IP list node */
struct IPListNode {
	RB_ENTRY(IPListNode) entry;
	uint64_t	ip[2];
	uint64_t	mask[2];
};

/* Definition of the port/AS list node */
struct ULongListNode {
	RB_ENTRY(ULongListNode) entry;
	uint64_t	value;
};


/* 
 * Filter Engine Functions
 */
int RunFilter(FilterEngine_data_t *args);
int RunExtendedFilter(FilterEngine_data_t *args);
/*
 * For testing purpose only
 */
int nblocks(void);

/*
 * Initialize globals
 */
void InitTree(void);

/*
 * Returns the current Filter Tree
 */
FilterEngine_data_t *CompileFilter(char *FilterSyntax);

/*
 * Clear Filter
 */
void ClearFilter(void);

/* 
 * Returns next free slot in blocklist
 */
uint32_t	NewBlock(uint32_t offset, uint64_t mask, uint64_t value, uint16_t comp, uint32_t function, void *data);
uint32_t NewBlock1(off_t field, BlockValue d , uint16_t comp, uint32_t function, void *data);
/* 
 * Connects the to blocks b1 and b2 ( AND ) and returns index of superblock
 */
uint32_t	Connect_AND(uint32_t b1, uint32_t b2);

/* 
 * Connects the to blocks b1 and b2 ( OR ) and returns index of superblock
 */
uint32_t	Connect_OR(uint32_t b1, uint32_t b2);

/* 
 * Inverts OnTrue and OnFalse
 */
uint32_t	Invert(uint32_t a );

/* 
 * Add Ident to Identlist
 */
uint32_t AddIdent(char *Ident);

/*
 * Dump Filterlist 
 */
void DumpList(FilterEngine_data_t *args);

/* 
 * Prints info while filer is running
 */
int RunDebugFilter(uint32_t	*block);

#endif //_NFTREE_H

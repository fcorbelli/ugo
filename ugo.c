/*
	ugo	2
	Reworked SHA-1 HW hasher, based on
	Igor Pavlov (7zip) work and Shelwien (admin of encode.ru)
	
	By Franco Corbelli
	
	Experimental software for AMD Ryzen (maybe newer Intel CPUs) on Windows64
	g++ -march=native -s -O3 -static ugo.c sha1ugo.obj -o ugo.exe
	
	To make the sha1ugo.obj from sha1ugo.asm use
	https://github.com/nidud/asmc 
	asmc64.exe sha1ugo.asm 

*/


#include <stdio.h>
#include <string>
#include <windows.h>

#define _FILE_OFFSET_BITS 64  

#define MY_ALIGN(n) __attribute__ ((aligned(n)))
#define MY_NO_INLINE __attribute__((noinline))
#define MY_FAST_CALL

typedef unsigned char 			Byte;
typedef short 					Int16;
typedef int 					Int32;
typedef long long int 			Int64;
typedef unsigned short 			UInt16;
typedef unsigned int 			UInt32;
typedef unsigned long long int 	UInt64;
typedef int 					BoolInt;


#define SHA1_NUM_BLOCK_WORDS  16
#define SHA1_NUM_DIGEST_WORDS  5
#define SHA1_BLOCK_SIZE   (SHA1_NUM_BLOCK_WORDS * 4)
#define SHA1_DIGEST_SIZE  (SHA1_NUM_DIGEST_WORDS * 4)
typedef void (MY_FAST_CALL *SHA1_FUNC_UPDATE_BLOCKS)(UInt32 state[5], const Byte *data, size_t numBlocks);

typedef struct
{
  SHA1_FUNC_UPDATE_BLOCKS func_UpdateBlocks;
  UInt64 count;
  UInt64 __pad_2[2];
  UInt32 state[SHA1_NUM_DIGEST_WORDS];
  UInt32 __pad_3[3];
  Byte buffer[SHA1_BLOCK_SIZE];
} CSha1;

/*
call Sha1Prepare() once at program start manually set for HW
*/
void Sha1Prepare(bool i_flaghardware=false);

void Sha1_InitState(CSha1 *p);
void Sha1_Init(CSha1 *p);
void Sha1_Update(CSha1 *p, const Byte *data, size_t size);
void Sha1_Final			(CSha1 *p, Byte *digest);
void Sha1_PrepareBlock(const CSha1 *p, Byte *block, unsigned size);
void Sha1_GetBlockDigest(const CSha1 *p, const Byte *data, Byte *destDigest);

void MY_FAST_CALL Sha1_UpdateBlocks(UInt32 state[5], const Byte *data, size_t numBlocks);

extern "C" void MY_FAST_CALL Sha1_UpdateBlocks_HW(UInt32 state[5], const Byte *data, size_t numBlocks);

static SHA1_FUNC_UPDATE_BLOCKS g_FUNC_UPDATE_BLOCKS = Sha1_UpdateBlocks;
static SHA1_FUNC_UPDATE_BLOCKS g_FUNC_UPDATE_BLOCKS_HW;

#define rotlFixed(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define rotrFixed(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define STEP_PRE  20
#define STEP_MAIN 20
#define kNumW 16
#define w(i) W[(i)&15]

#define w0(i) (W[i] = GetBe32(data + (size_t)(i) * 4))
#define w1(i) (w(i) = rotlFixed(w((size_t)(i)-3) ^ w((size_t)(i)-8) ^ w((size_t)(i)-14) ^ w((size_t)(i)-16), 1))

#define f0(x,y,z)  ( 0x5a827999 + (z^(x&(y^z))) )
#define f1(x,y,z)  ( 0x6ed9eba1 + (x^y^z) )
#define f2(x,y,z)  ( 0x8f1bbcdc + ((x&y)|(z&(x|y))) )
#define f3(x,y,z)  ( 0xca62c1d6 + (x^y^z) )

#define T5(a,b,c,d,e, fx, ww) \
    e += fx(b,c,d) + ww + rotlFixed(a, 5); \
    b = rotlFixed(b, 30); \

#define M5(i, fx, wx0, wx1) \
    T5 ( a,b,c,d,e, fx, wx0((i)  ) ); \
    T5 ( e,a,b,c,d, fx, wx1((i)+1) ); \
    T5 ( d,e,a,b,c, fx, wx1((i)+2) ); \
    T5 ( c,d,e,a,b, fx, wx1((i)+3) ); \
    T5 ( b,c,d,e,a, fx, wx1((i)+4) ); \

#define R5(i, fx, wx) \
    M5 ( i, fx, wx, wx) \


#if STEP_PRE > 5

  #define R20_START \
    R5 (  0, f0, w0); \
    R5 (  5, f0, w0); \
    R5 ( 10, f0, w0); \
    M5 ( 15, f0, w0, w1); \
  
  #elif STEP_PRE == 5
  
  #define R20_START \
    { size_t i; for (i = 0; i < 15; i += STEP_PRE) \
      { R5(i, f0, w0); } } \
    M5 ( 15, f0, w0, w1); \

#else

  #if STEP_PRE == 1
    #define R_PRE R1
  #elif STEP_PRE == 2
    #define R_PRE R2
  #elif STEP_PRE == 4
    #define R_PRE R4
  #endif

  #define R20_START \
    { size_t i; for (i = 0; i < 16; i += STEP_PRE) \
      { R_PRE(i, f0, w0); } } \
    R4 ( 16, f0, w1); \

#endif

#if STEP_MAIN > 5

  #define R20(ii, fx) \
    R5 ( (ii)     , fx, w1); \
    R5 ( (ii) + 5 , fx, w1); \
    R5 ( (ii) + 10, fx, w1); \
    R5 ( (ii) + 15, fx, w1); \

#else

  #if STEP_MAIN == 1
    #define R_MAIN R1
  #elif STEP_MAIN == 2
    #define R_MAIN R2
  #elif STEP_MAIN == 4
    #define R_MAIN R4
  #elif STEP_MAIN == 5
    #define R_MAIN R5
  #endif

  #define R20(ii, fx)  \
    { size_t i; for (i = (ii); i < (ii) + 20; i += STEP_MAIN) \
      { R_MAIN(i, fx, w1); } } \

#endif


#define SetUi32(p, v) { *(UInt32 *)(void *)(p) = (v); }
#define GetBe32(p) ( \
    ((UInt32)((const Byte *)(p))[0] << 24) | \
    ((UInt32)((const Byte *)(p))[1] << 16) | \
    ((UInt32)((const Byte *)(p))[2] <<  8) | \
             ((const Byte *)(p))[3] )
#define SetBe32(p, v) { Byte *_ppp_ = (Byte *)(p); UInt32 _vvv_ = (v); \
    _ppp_[0] = (Byte)(_vvv_ >> 24); \
    _ppp_[1] = (Byte)(_vvv_ >> 16); \
    _ppp_[2] = (Byte)(_vvv_ >> 8); \
    _ppp_[3] = (Byte)_vvv_; }


void Sha1_InitState(CSha1 *p)
{
	p->count = 0;
	p->state[0] = 0x67452301;
	p->state[1] = 0xEFCDAB89;
	p->state[2] = 0x98BADCFE;
	p->state[3] = 0x10325476;
	p->state[4] = 0xC3D2E1F0;
}

void Sha1_Init(CSha1 *p)
{
	p->func_UpdateBlocks =     g_FUNC_UPDATE_BLOCKS;
	Sha1_InitState(p);
}


MY_NO_INLINE
void MY_FAST_CALL Sha1_UpdateBlocks(UInt32 state[5], const Byte *data, size_t numBlocks)
{
	UInt32 a, b, c, d, e;
	UInt32 W[kNumW];
	// if (numBlocks != 0x1264378347) return;
	if (numBlocks==0)
		return;

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	do
	{
		#if STEP_PRE < 5 || STEP_MAIN < 5
		UInt32 tmp;
		#endif

		R20_START
		R20(20, f1);
		R20(40, f2);
		R20(60, f3);

		a += state[0];
		b += state[1];
		c += state[2];
		d += state[3];
		e += state[4];

		state[0] = a;
		state[1] = b;
		state[2] = c;
		state[3] = d;
		state[4] = e;

		data += 64;
	}
	while (--numBlocks);
}

void Sha1_Update(CSha1 *p, const Byte *data, size_t size)
{
	if (size==0)
		return;

	unsigned pos = (unsigned)p->count & 0x3F;
	unsigned num;

	p->count += size;

	num=64-pos;
	if (num > size)
	{
		memcpy(p->buffer + pos, data, size);
		return;
	}

	if (pos != 0)
	{
		size -= num;
		memcpy(p->buffer + pos, data, num);
		data += num;
		p->func_UpdateBlocks(p->state, p->buffer, 1);
	}

	size_t numBlocks = size >> 6;
	p->func_UpdateBlocks(p->state, data, numBlocks);
	size &= 0x3F;
	if (size==0)
	  return;
	data += (numBlocks << 6);
	memcpy(p->buffer, data, size);
}


void Sha1_Final(CSha1 *p, Byte *digest)
{
	unsigned pos = (unsigned)p->count & 0x3F;
  
	p->buffer[pos++] = 0x80;

	if (pos > (64 - 8))
	{
		while (pos != 64) 
			p->buffer[pos++]=0; 
		// memset(&p->buf.buffer[pos], 0, 64 - pos);
		p->func_UpdateBlocks(p->state, p->buffer, 1);
		pos = 0;
	}

	memset(&p->buffer[pos], 0, (64 - 8) - pos);
  
	UInt64 numBits = (p->count << 3);
    SetBe32(p->buffer + 64 - 8, (UInt32)(numBits >> 32));
    SetBe32(p->buffer + 64 - 4, (UInt32)(numBits));
 
	p->func_UpdateBlocks(p->state, p->buffer, 1);

	SetBe32(digest,      p->state[0]);
	SetBe32(digest + 4,  p->state[1]);
	SetBe32(digest + 8,  p->state[2]);
	SetBe32(digest + 12, p->state[3]);
	SetBe32(digest + 16, p->state[4]);
	Sha1_InitState(p);
}


void Sha1_PrepareBlock(const CSha1 *p, Byte *block, unsigned size)
{
	const UInt64 numBits = (p->count + size) << 3;
	SetBe32(&((UInt32 *)(void *)block)[SHA1_NUM_BLOCK_WORDS - 2], (UInt32)(numBits >> 32));
	SetBe32(&((UInt32 *)(void *)block)[SHA1_NUM_BLOCK_WORDS - 1], (UInt32)(numBits));
	// SetBe32((UInt32 *)(block + size), 0x80000000);
	SetUi32((UInt32 *)(void *)(block + size), 0x80);
	size += 4;
	while (size != (SHA1_NUM_BLOCK_WORDS - 2) * 4)
	{
		*((UInt32 *)(void *)(block + size)) = 0;
		size += 4;
	}
}

void Sha1_GetBlockDigest(const CSha1 *p, const Byte *data, Byte *destDigest)
{
	MY_ALIGN (16)
	UInt32 st[SHA1_NUM_DIGEST_WORDS];

	st[0] = p->state[0];
	st[1] = p->state[1];
	st[2] = p->state[2];
	st[3] = p->state[3];
	st[4] = p->state[4];

	p->func_UpdateBlocks(st, data, 1);

	SetBe32(destDigest + 0    , st[0]);
	SetBe32(destDigest + 1 * 4, st[1]);
	SetBe32(destDigest + 2 * 4, st[2]);
	SetBe32(destDigest + 3 * 4, st[3]);
	SetBe32(destDigest + 4 * 4, st[4]);
}


void Sha1Prepare(bool i_flaghardware)
{
	SHA1_FUNC_UPDATE_BLOCKS f, f_hw;
	f = Sha1_UpdateBlocks;
	if (i_flaghardware)
		f = f_hw = Sha1_UpdateBlocks_HW;
	g_FUNC_UPDATE_BLOCKS    = f;
	g_FUNC_UPDATE_BLOCKS_HW = f_hw;
}



/*
	How to use?
*/

int64_t prendidimensionefile(const char* i_filename)
{
	if (!i_filename)
		return 0;
	FILE* myfile = fopen(i_filename,"rb");
	if (myfile)
    {
		fseeko(myfile, 0, SEEK_END);
		int64_t dimensione=ftello(myfile);
		fclose(myfile);
		return dimensione;
	}
	else
	return 0;
}
inline char *  migliaia(uint64_t n)
{
	static char retbuf[30];
	char *p = &retbuf[sizeof(retbuf)-1];
	unsigned int i = 0;
	*p = '\0';
	do 
	{
		if(i%3 == 0 && i != 0)
			*--p = '.';
		*--p = '0' + n % 10;
		n /= 10;
		i++;
		} while(n != 0);
	return p;
}


std::string	binarytohex(const unsigned char* i_risultato,const int i_lunghezza)
{
	std::string risultato="";
	char myhex[4];
	
	if (i_risultato!=NULL)
		if (i_lunghezza>0)
			for (int j=0;j<i_lunghezza;j++)
			{
				sprintf(myhex,"%02X", (unsigned char)i_risultato[j]);
				risultato.push_back(myhex[0]);
				risultato.push_back(myhex[1]);
			}
	return risultato;
}

std::string sha1_calc_file(const char * i_filename)
{
	FILE* myfile = fopen(i_filename,"rb");
	
	if(myfile==NULL )
	{
		printf("Error on file\n");
		return "";
	}
	const int BUFSIZE	=65536*8;
	char 				unzBuf[BUFSIZE];
	int 				n=BUFSIZE;
	
	CSha1	myhasher;
	Sha1_Init	(&myhasher);
	
	int64_t start=GetTickCount();
  
	while (1)
	{
		int r=fread(unzBuf, 1, n, myfile);
		Sha1_Update	(&myhasher,(const Byte*)unzBuf,r);
		if (r!=n) 
			break;
	}
	int64_t end=GetTickCount();
	fclose(myfile);
	
	float	tempo=(end-start+1)/1000.0;
	int64_t dimensione=prendidimensionefile(i_filename);
	int64_t	velocita=dimensione/tempo;
	printf("Time %f %s /s\n",tempo,migliaia(velocita));
	
	char sha1result[20];
	Sha1_Final	(&myhasher,(Byte*)sha1result);
	return binarytohex((const unsigned char*)sha1result,20);
}

int main(int argc, char *argv[])
{
	/*
	OK this is very quick and dirty.
	The sorter, the better
	*/
	char command;
	if (argc>=2)
		command=argv[1][0];
		
	if ((argc!=3) || (command!='h') && (command!='s'))
	{
		printf("Ugo 2 HW-SHA-1 hasher - by Franco Corbelli\n");
		printf("Two parameters: h or s and a file\n");
		printf("ex. ugo h z:\\1.txt   (hardware-accelerated SHA-1)\n");
		printf("ex. ugo s z:\\1.txt   (software-based SHA-1)\n");
		return 1;
	}
	
	Sha1Prepare(command=='h');
	printf("Hashing %s\n",argv[2]);
	std::string risultato=sha1_calc_file(argv[2]);
	printf("SHA1 %s\n",risultato.c_str());
	return 0;
}

//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// skywind3000 (at) gmail.com, 2010-2011
//  
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//
//=====================================================================
#include "ikcp.h"

#include <string.h>
#include <stdarg.h>
#include <stdio.h>



//=====================================================================
// KCP BASIC
//=====================================================================
const IUINT32 IKCP_RTO_NDL = 30;		// no delay min rto
const IUINT32 IKCP_RTO_MIN = 100;		// normal min rto
const IUINT32 IKCP_RTO_DEF = 200;
const IUINT32 IKCP_RTO_MAX = 60000;

const IUINT32 IKCP_CMD_PUSH = 81;		// cmd: push data
const IUINT32 IKCP_CMD_ACK  = 82;		// cmd: ack

const IUINT32 IKCP_CMD_WASK = 83;		// cmd: window probe (ask)
const IUINT32 IKCP_CMD_WINS = 84;		// cmd: window size (tell)

const IUINT32 IKCP_ASK_SEND = 1;		// need to send IKCP_CMD_WASK
const IUINT32 IKCP_ASK_TELL = 2;		// need to send IKCP_CMD_WINS

const IUINT32 IKCP_WND_SND = 32;
const IUINT32 IKCP_WND_RCV = 32;

const IUINT32 IKCP_MTU_DEF = 1400;

const IUINT32 IKCP_ACK_FAST	= 3;

const IUINT32 IKCP_INTERVAL	= 100;

const IUINT32 IKCP_OVERHEAD = 24;

const IUINT32 IKCP_DEADLINK = 20;

const IUINT32 IKCP_THRESH_INIT = 2;
const IUINT32 IKCP_THRESH_MIN = 2;

const IUINT32 IKCP_PROBE_INIT = 7000;		// 7 secs to probe window size
const IUINT32 IKCP_PROBE_LIMIT = 120000;	// up to 120 secs to probe window


//---------------------------------------------------------------------
// encode / decode
//---------------------------------------------------------------------

/* encode 8 bits unsigned int */
static inline char *ikcp_encode8u(char *p, unsigned char c)
{
	*(unsigned char*)p++ = c;
	return p;
}

/* decode 8 bits unsigned int */
static inline const char *ikcp_decode8u(const char *p, unsigned char *c)
{
	*c = *(unsigned char*)p++;
	return p;
}

/* encode 16 bits unsigned int (lsb) */
static inline char *ikcp_encode16u(char *p, unsigned short w)
{
#if IWORDS_BIG_ENDIAN
	*(unsigned char*)(p + 0) = (w & 255);
	*(unsigned char*)(p + 1) = (w >> 8);
#else
	*(unsigned short*)(p) = w;
#endif
	p += 2;
	return p;
}

/* decode 16 bits unsigned int (lsb) */
static inline const char *ikcp_decode16u(const char *p, unsigned short *w)
{
#if IWORDS_BIG_ENDIAN
	*w = *(const unsigned char*)(p + 1);
	*w = *(const unsigned char*)(p + 0) + (*w << 8);
#else
	*w = *(const unsigned short*)p;
#endif
	p += 2;
	return p;
}

/* encode 32 bits unsigned int (lsb) */
static inline char *ikcp_encode32u(char *p, IUINT32 l)
{
#if IWORDS_BIG_ENDIAN
	*(unsigned char*)(p + 0) = (unsigned char)((l >>  0) & 0xff);
	*(unsigned char*)(p + 1) = (unsigned char)((l >>  8) & 0xff);
	*(unsigned char*)(p + 2) = (unsigned char)((l >> 16) & 0xff);
	*(unsigned char*)(p + 3) = (unsigned char)((l >> 24) & 0xff);
#else
	*(IUINT32*)p = l;
#endif
	p += 4;
	return p;
}

/* decode 32 bits unsigned int (lsb) */
static inline const char *ikcp_decode32u(const char *p, IUINT32 *l)
{
#if IWORDS_BIG_ENDIAN
	*l = *(const unsigned char*)(p + 3);
	*l = *(const unsigned char*)(p + 2) + (*l << 8);
	*l = *(const unsigned char*)(p + 1) + (*l << 8);
	*l = *(const unsigned char*)(p + 0) + (*l << 8);
#else 
	*l = *(const IUINT32*)p;
#endif
	p += 4;
	return p;
}

static inline IUINT32 _imin_(IUINT32 a, IUINT32 b) {
	return a <= b ? a : b;
}

static inline IUINT32 _imax_(IUINT32 a, IUINT32 b) {
	return a >= b ? a : b;
}

// return the value in the middle
static inline IUINT32 _ibound_(IUINT32 lower, IUINT32 middle, IUINT32 upper) 
{
	return _imin_(_imax_(lower, middle), upper);
}

static inline long _itimediff(IUINT32 later, IUINT32 earlier) 
{
	return ((IINT32)(later - earlier));
}

//---------------------------------------------------------------------
// manage segment
//---------------------------------------------------------------------
typedef struct IKCPSEG IKCPSEG;

static void* (*ikcp_malloc_hook)(size_t) = NULL;
static void (*ikcp_free_hook)(void *) = NULL;

// internal malloc
static void* ikcp_malloc(size_t size) {
	if (ikcp_malloc_hook) 
		return ikcp_malloc_hook(size);
	return malloc(size);
}

// internal free
static void ikcp_free(void *ptr) {
	if (ikcp_free_hook) {
		ikcp_free_hook(ptr);
	}	else {
		free(ptr);
	}
}

// redefine allocator
void ikcp_allocator(void* (*new_malloc)(size_t), void (*new_free)(void*))
{
	ikcp_malloc_hook = new_malloc;
	ikcp_free_hook = new_free;
}

// allocate a new kcp segment
static IKCPSEG* ikcp_segment_new(ikcpcb *kcp, int size)
{
	return (IKCPSEG*)ikcp_malloc(sizeof(IKCPSEG) + size);
}

// delete a segment
static void ikcp_segment_delete(ikcpcb *kcp, IKCPSEG *seg)
{
	ikcp_free(seg);
}

// write log
void ikcp_log(ikcpcb *kcp, int mask, const char *fmt, ...)
{
	char buffer[1024];
	va_list argptr;
	if ((mask & kcp->logmask) == 0 || kcp->writelog == 0) return;
	va_start(argptr, fmt);
	vsprintf(buffer, fmt, argptr);
	va_end(argptr);
	kcp->writelog(buffer, kcp, kcp->user);
}

// check log mask
static int ikcp_canlog(const ikcpcb *kcp, int mask)
{
	if ((mask & kcp->logmask) == 0 || kcp->writelog == NULL) return 0;
	return 1;
}

// output segment
// 简单来说，ikcp_output就是直接调用我们的output_wrappers
static int ikcp_output(ikcpcb *kcp, const void *data, int size)
{
	assert(kcp);
	assert(kcp->output);
	if (ikcp_canlog(kcp, IKCP_LOG_OUTPUT)) {
		ikcp_log(kcp, IKCP_LOG_OUTPUT, "[RO] %ld bytes", (long)size);
	}
	if (size == 0) return 0;
	return kcp->output((const char*)data, size, kcp, kcp->user);
}

// output queue
void ikcp_qprint(const char *name, const struct IQUEUEHEAD *head)
{
#if 0
	const struct IQUEUEHEAD *p;
	printf("<%s>: [", name);
	for (p = head->next; p != head; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		printf("(%lu %d)", (unsigned long)seg->sn, (int)(seg->ts % 10000));
		if (p->next != head) printf(",");
	}
	printf("]\n");
#endif
}


//---------------------------------------------------------------------
// create a new kcpcb
//---------------------------------------------------------------------
ikcpcb* ikcp_create(IUINT32 conv, void *user)
{
	ikcpcb *kcp = (ikcpcb*)ikcp_malloc(sizeof(struct IKCPCB));
	if (kcp == NULL) return NULL;

	kcp->conv = conv;
	kcp->user = user;

	kcp->snd_una = 0;
	kcp->snd_nxt = 0;
	kcp->rcv_nxt = 0;

	kcp->ts_recent = 0;
	kcp->ts_lastack = 0;
	kcp->ts_probe = 0;  // timestamp

	kcp->probe_wait = 0;

	kcp->snd_wnd = IKCP_WND_SND;
	kcp->rcv_wnd = IKCP_WND_RCV;
	kcp->rmt_wnd = IKCP_WND_RCV;
	kcp->cwnd = 0;

	kcp->incr = 0;
	kcp->probe = 0;
	kcp->mtu = IKCP_MTU_DEF;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	kcp->stream = 0;

	kcp->buffer = (char*)ikcp_malloc((kcp->mtu + IKCP_OVERHEAD) * 3);
	if (kcp->buffer == NULL) {
		ikcp_free(kcp);
		return NULL;
	}

    /*
     *  数据结构是整个ARQ协议的核心，决定了整体的运作方式
     *  带头结点的双向循环列表
     */
	iqueue_init(&kcp->snd_queue);
	iqueue_init(&kcp->snd_buf);
    iqueue_init(&kcp->rcv_queue);
    iqueue_init(&kcp->rcv_buf);

	kcp->nsnd_que = 0;
    kcp->nrcv_que = 0;
    kcp->nsnd_buf = 0;
    kcp->nrcv_buf = 0;

	kcp->state = 0;

	kcp->acklist = NULL;
	kcp->ackblock = 0;  // capacity of acklist
	kcp->ackcount = 0;  // count of elelments

	kcp->rx_srtt = 0;
	kcp->rx_rttval = 0;
	kcp->rx_rto = IKCP_RTO_DEF;
	kcp->rx_minrto = IKCP_RTO_MIN;

	kcp->current = 0;
	kcp->interval = IKCP_INTERVAL;
	kcp->ts_flush = IKCP_INTERVAL;
	kcp->nodelay = 0;
	kcp->updated = 0;
	kcp->logmask = 0;
	kcp->ssthresh = IKCP_THRESH_INIT;
	kcp->fastresend = 0;
	kcp->nocwnd = 0;
	kcp->xmit = 0;
    kcp->dead_link = IKCP_DEADLINK;
	kcp->output = NULL;
	kcp->writelog = NULL;

	return kcp;
}


//---------------------------------------------------------------------
// release a new kcpcb
//---------------------------------------------------------------------
void ikcp_release(ikcpcb *kcp)
{
	assert(kcp);
	if (kcp) {
		IKCPSEG *seg;
		while (!iqueue_is_empty(&kcp->snd_buf)) {
			seg = iqueue_entry(kcp->snd_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_buf)) {
			seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->snd_queue)) {
			seg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_queue)) {
			seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		if (kcp->buffer) {
			ikcp_free(kcp->buffer);
		}
		if (kcp->acklist) {
			ikcp_free(kcp->acklist);
		}

		kcp->nrcv_buf = 0;
		kcp->nsnd_buf = 0;
		kcp->nrcv_que = 0;
		kcp->nsnd_que = 0;
		kcp->ackcount = 0;
		kcp->buffer = NULL;
		kcp->acklist = NULL;
		ikcp_free(kcp);
	}
}


//---------------------------------------------------------------------
// set output callback, which will be invoked by kcp
//---------------------------------------------------------------------
void ikcp_setoutput(ikcpcb *kcp, int (*output)(const char *buf, int len,
	ikcpcb *kcp, void *user))
{
	kcp->output = output;
}


//---------------------------------------------------------------------
// user/upper level recv: returns size, returns below zero for EAGAIN
// ikcp_recv函数的第一步：如果可行的话，就从recv_queue当中读取用户将要接收的下一个数据块，
// 当中可能涉及重组fragmentation。这里还原出来的数据块，应该是指发送方当初交给kcp，是什么样子的，
// 这边放在buffer当中的，就应该是什么样子的。
// 第二步：将rcv_buf当中已经按序到达的数据包，移至rcv_queue当中
//---------------------------------------------------------------------
int ikcp_recv(ikcpcb *kcp, char *buffer, int len)
{
	struct IQUEUEHEAD *p;
	int ispeek = (len < 0)? 1 : 0;
	int peeksize;
	int recover = 0;
	IKCPSEG *seg;
	assert(kcp);

	if (iqueue_is_empty(&kcp->rcv_queue))
		return -1;

	if (len < 0) len = -len;

	// ikcp_peeksize保证了peeksize的值要么是一个未进行过fragment的完整数据块的长度；
	// 要么是经过fragment，但是是最终拼接后的完整数据块长度
	// 总而言之，返回值都是完整数据块长度
	// 调用者，调用peeksize的目的，就是为了保证后面能够恢复出完整的数据包到buffer当中
    peeksize = ikcp_peeksize(kcp);

	if (peeksize < 0) 
		return -2;

	if (peeksize > len) 
		return -3;

    // 接受队列中的包个数比接收窗口大 ??
	if (kcp->nrcv_que >= kcp->rcv_wnd)
		recover = 1;

	// 在buffer当中重组fragment，这样buffer当中存放的就是用户将要接收的下一个数据块
	for (len = 0, p = kcp->rcv_queue.next; p != &kcp->rcv_queue; ) {
		seg = iqueue_entry(p, IKCPSEG, node);
        p = p->next;    // 为什么要在这里就先更新p呢？ 因为后面其所在的seg将会被free掉

		if (buffer) {
			memcpy(buffer, seg->data, seg->len);
			buffer += seg->len;
		}

        len += seg->len;    // 正常情况下，len的最终值必然等于peeksize
        int fragment = seg->frg;

		if (ikcp_canlog(kcp, IKCP_LOG_RECV)) {
			ikcp_log(kcp, IKCP_LOG_RECV, "recv sn=%lu", seg->sn);
		}

        if (!ispeek) {
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
			kcp->nrcv_que--;
		}

		if (fragment == 0) 
			break;
	}

	assert(len == peeksize);

	// move available data from rcv_buf -> rcv_queue
	// 从rcv_buf当中
	while (! iqueue_is_empty(&kcp->rcv_buf)) {
		IKCPSEG *seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
		if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
			iqueue_del(&seg->node);
			kcp->nrcv_buf--;
			iqueue_add_tail(&seg->node, &kcp->rcv_queue);
			kcp->nrcv_que++;
			kcp->rcv_nxt++;
		}	else {
			break;
		}
	}

	// fast recover
	// 是不是可以理解成之前接收窗口用完了，在把部分数据传给用户之后，
	// 重新告知对端目前的接收窗口大小，以实现流控
	if (kcp->nrcv_que < kcp->rcv_wnd && recover) {
		// ready to send back IKCP_CMD_WINS in ikcp_flush
		// tell remote my window size
		kcp->probe |= IKCP_ASK_TELL;
	}

	return len;
}


//---------------------------------------------------------------------
// peek data size
//
// 首先peek的对象是rcv_queue，用户取数据将会从这里取
// rcv_queue任意一个时刻存放的都是"有序的"数据,用户可以放心地拿走
// 可能某个数据包已经到达，但是在这个数据包之前的某个数据包还未到到达，
// 那么这个数据包就只能继续待在rcv_buf当中
// 也就是说rcv_queue给用户提供了一个可靠服务的抽象，
// 乱序、丢包等情况的处理都隐藏在rcv_buf当中进行
//
// 其实现细节就是函数会先看queue当中的第一个seg，也就是最早的seg
// 如果这个seg是完整的，而非一个fragmentation，那么返回其大小即可
// 但是，如果这个seg是一个fragmentation，且queue当中包含了其余剩下的fragmentation，
// 那么就返回所有fragmentation大小的之和
//
// 从函数实现的意图来说，每次调用该函数，都给出了下一个将要收到的完整数据包的大小
//---------------------------------------------------------------------
int ikcp_peeksize(const ikcpcb *kcp)
{
	struct IQUEUEHEAD *p;
	IKCPSEG *seg;
	int length = 0;

	assert(kcp);

	if (iqueue_is_empty(&kcp->rcv_queue)) return -1;

	seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
	if (seg->frg == 0) return seg->len;

    if (kcp->nrcv_que < seg->frg + 1) return -1;    // 这句话，保证了peeksize窥探到的都是（重组后）的完整数据块的长度

	for (p = kcp->rcv_queue.next; p != &kcp->rcv_queue; p = p->next) {
		seg = iqueue_entry(p, IKCPSEG, node);
		length += seg->len;
		if (seg->frg == 0) break;
	}

	return length;
}


//---------------------------------------------------------------------
// user/upper level send, returns below zero for error
// snd_queue
//---------------------------------------------------------------------
int ikcp_send(ikcpcb *kcp, const char *buffer, int len)
{
	IKCPSEG *seg;
	int count, i;

	assert(kcp->mss > 0);
	if (len < 0) return -1;

    // stream mode 字节流模式 无消息边界
    // 简单来说，就是尽可能地将数据追加到等待发送的数据包的尾部
	// append to previous segment in streaming mode (if possible)
	if (kcp->stream != 0) {
		if (!iqueue_is_empty(&kcp->snd_queue)) {
			IKCPSEG *old = iqueue_entry(kcp->snd_queue.prev, IKCPSEG, node);
			if (old->len < kcp->mss) {
				int capacity = kcp->mss - old->len;
				int extend = (len < capacity)? len : capacity;
				seg = ikcp_segment_new(kcp, old->len + extend);
				assert(seg);
				if (seg == NULL) {
					return -2;
				}
				iqueue_add_tail(&seg->node, &kcp->snd_queue);

				memcpy(seg->data, old->data, old->len);
				if (buffer) {
					memcpy(seg->data + old->len, buffer, extend);
					buffer += extend;
				}
				seg->len = old->len + extend;
				seg->frg = 0;
				len -= extend;

				iqueue_del_init(&old->node);
				ikcp_segment_delete(kcp, old);
			}
		}
		if (len <= 0) {
			return 0;
		}
	}
    /*
     * 为什么要在实现超时重传的同时，实现分片呢？
     *
     * 这里，首先说明下背景知识
     * ip的确会进行fragmentation，也就是说当一块数据超过了mtu，它就会被切分成多个小的ip包
     * 但是，请不要忘记ip是best effort的，不可靠的，一旦某个fragment在网络传输过程中丢失了，
     * 那么对端的ip层就没有办法将小的ip重组成原始的数据块。
     * 这时候，上层进行超时重传，就会导致实际上没有丢失的fragment被再次发了一遍。
     */

	if (len <= (int)kcp->mss) count = 1;
	else count = (len + kcp->mss - 1) / kcp->mss;

	if (count > 255) return -2;

	if (count == 0) count = 1;

	// fragment
    // 依据mss，将实际数据切分成块.最后一块中，实际数据大小可能不足mss
	// 为每一块数据加一个IKCPSEG结构体的头部，然后将其串到snd_queue当中
	// 注意，不同于ikcp_recv,ikcp_send当中只牵涉了snd_buf
	for (i = 0; i < count; i++) {
		int size = len > (int)kcp->mss ? (int)kcp->mss : len;
		seg = ikcp_segment_new(kcp, size);
		assert(seg);
		if (seg == NULL) {
			return -2;
		}
		if (buffer && len > 0) {
			memcpy(seg->data, buffer, size);
		}
		seg->len = size;
        seg->frg = (kcp->stream == 0) ? (count - i - 1) : 0; // seg->frag的值表示在这个包之后还有多少个fragment

		iqueue_init(&seg->node);
		iqueue_add_tail(&seg->node, &kcp->snd_queue);
		kcp->nsnd_que++;

        if (buffer)
			buffer += size;
		len -= size;
	}

	return 0;
}


//---------------------------------------------------------------------
// parse ack
//---------------------------------------------------------------------
static void ikcp_update_ack(ikcpcb *kcp, IINT32 rtt)
{
	IINT32 rto = 0;
	if (kcp->rx_srtt == 0) {								// one-shot initialization
		kcp->rx_srtt = rtt;									// srtt = rtt;
		kcp->rx_rttval = rtt / 2;							// rttval = rtt / 2;
	}	else {
		long delta = rtt - kcp->rx_srtt;
		if (delta < 0) delta = -delta;						// delta = abs(rtt - srtt);
		kcp->rx_rttval = (3 * kcp->rx_rttval + delta) / 4;	// rttval = (3/4) * rttval + (1/4) * delta;
		kcp->rx_srtt = (7 * kcp->rx_srtt + rtt) / 8;		// srtt = (7/8) * srtt + (1/8) * rtt;
		if (kcp->rx_srtt < 1) kcp->rx_srtt = 1;
	}
	rto = kcp->rx_srtt + _imax_(kcp->interval, 4 * kcp->rx_rttval);
	kcp->rx_rto = _ibound_(kcp->rx_minrto, rto, IKCP_RTO_MAX);
	// 这里，明确了为什么这个函数叫做_ibound_
	// 计算出来的rto，应该在minrto和RTO_MAX这两个边界值之间
	// 如果的确超过了范围，就取边界值
}

/*
 * 回想滑动窗口被分割成4部分
 *
 * 第一部分已经发送且被确认了（没有保留的价值了，不占用任何存储空间）
 * 第二部分已经发送但还未确认 （由于可能需要重传，故需要一个地方保存这些数据，就是snd_buf)
 * 第三部分还未发送但是允许发送 （这部分的数据，用户都还没有交付进来，无从谈起）
 * 第四部分不允许发送
 *
 * una指向第二部分的开头，任何比una值小的seg都已经被ack，即成功发送了
 * snd_buf保存的就是第二部分的东西
 * 在第二部分非空情况下，snd_una就等同于snd_buf中首个元素的seqid
 * snd_nxt是第三部分中首个元素的seqid
 * 在第二部分空的情况下，snd_una = snd_nxt
 * 二者等价
 *
 * 如果snd_buf非空，也就是第二部分非空，那么snd_una的值就是第一个seg的sn
 * 如果snd_buf为空，也就是第二部分空，那么snd_una的值就应该是snd_nxt
 */
static void ikcp_shrink_buf(ikcpcb *kcp)
{
    struct IQUEUEHEAD *p = kcp->snd_buf.next;
    if (p != &kcp->snd_buf) {	// snd_buf非空时
        IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
        kcp->snd_una = seg->sn;
    }	else {
        kcp->snd_una = kcp->snd_nxt;
    }
}

/*
 * 针对接收到的ack进行解析处理
 * 注意，在这里，只是针对收到的ack，看看能不能从snd_buf中删去相应的数据包
 * 如果ack掉的正好是una对应的数据包，那么就涉及对una的处理，
 * 但是本函数并不负责，相应的责任由ikcp_shrink_buf实现
 *
 */
/*
 * 这个暂时保留
 * 也就是说，平时ikcp_parse_ack和ikcp_shrink_buf一般是组合使用的。
 * ikcp_parse_ack根据收到的ack整理snd_buf，
 * 而ikcp_shrink_buf根据ikcp_parse_ack所作出的调整，更新una
 * una就是snd_buf当中首个元素的sn（如果空，那么为nxt)
 */
static void ikcp_parse_ack(ikcpcb *kcp, IUINT32 sn)
{
    struct IQUEUEHEAD *p, *next;

    // 某个时候, 合法的ack应该在这样一个范围内: kcp->snd_una <= sn < kcp->snd_nxt
    // 如果某个ack不在这个范围内，那么就是无效的
    if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
        return;

    // 当我们收到某个ack之后，就在snd_buf中（也就是已经发送但是还未收到ack）寻找相对应的数据包
    // 如果找到了，就代表一个数据包成功被对端接收，不再需要进行重传等操作，可以从snd_buf中删去
    for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
        IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
        next = p->next;
        if (sn == seg->sn) {
            iqueue_del(p);
            ikcp_segment_delete(kcp, seg);
            kcp->nsnd_buf--;
            break;
        }
        // 如果出现snd_buf中上一个元素的sn < sn < snd_buf中当前一个元素的sn，
        // 那么sn正好夹在了沟里，无法找到匹配的
        // 简单来说，这只是利用了snd_buf本身有序的这一特性，对查找进行的优化
        // 将此语句删掉，并不影响实际函数的功能，只会影响其性能
        if (_itimediff(sn, seg->sn) < 0)
            break;
    }
}

/*
 * 继续上面的背景知识
 * 这个函数主要负责维护发送滑动窗口第一部分和第二部分之间的分界线
 * 第一部分是已经发送且已经成功被确认了的数据包，那么就没有任何保存的需要了，所以可以安全删去
 * 这个函数什么时候该被调用？当然是应该在una这个值更新之后。
 * 到目前为止，
 *
 * ikcp_parse_ack和ikcp_parse_una这两个函数的实现以及功能，都十分类似。
 * 但是，要注意ikcp_parse_ack是对单个数据包进行ack；
 * 而ikcp_parse_una是累计ACK，是对某个sn之前的所有数据包进行ack
 */
static void ikcp_parse_una(ikcpcb *kcp, IUINT32 una)
{
    struct IQUEUEHEAD *p, *next;
    for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
        IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
        next = p->next;
        if (_itimediff(seg->sn, una) < 0) {
            iqueue_del(p);
            ikcp_segment_delete(kcp, seg);
            kcp->nsnd_buf--;
        } else {
            break;
        }
    }
}

/*
 * 前面是有一个ikcp_parse_ack。它的作用呢，是从snd_buf中找到ack对应的seg，
 * 然后将它从snd_buf中删除。
 * ikcp_parse_fastack，虽然名字上看上去好相似，但实际上，其作用有较大的差别
 *
 * 作者在github上提到了这么一句：
 *
 * 发送端发送了1,2,3,4,5几个包，然后收到远端的ACK: 1, 3, 4, 5，
 * 当收到ACK3时，KCP知道2被跳过1次，收到ACK4时，知道2被跳过了2次，
 * 此时可以认为2号丢失，不用等超时，直接重传2号包，大大改善了丢包时的传输速度。
 *
 * ikcp_parse_fastack就是来计这个数的。
 * snd_buf当中保存的就是已经发送但是还在等待ack的seg
 * 要想计被跳过的数，那么在每次收到一个ack之后，就找这个ack对应的seg之前的seg，
 * 给这些个seg，都计一次数。
 *
 */
static void ikcp_parse_fastack(ikcpcb *kcp, IUINT32 sn)
{
	struct IQUEUEHEAD *p, *next;

    // snd_una <= sn < snd_nxt
	if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
		return;

	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		if (_itimediff(sn, seg->sn) < 0)
			break;
		else if (sn != seg->sn) // seg->sn < sn
			seg->fastack++;
	}
}


//---------------------------------------------------------------------
// ack append
//---------------------------------------------------------------------
static void ikcp_ack_push(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
	size_t newsize = kcp->ackcount + 1;
	IUINT32 *ptr;

	if (newsize > kcp->ackblock) {
		IUINT32 *acklist;
		size_t newblock;

        for (newblock = 8; newblock < newsize; newblock <<= 1);
		acklist = (IUINT32*)ikcp_malloc(newblock * sizeof(IUINT32) * 2);

		if (acklist == NULL) {
			assert(acklist != NULL);
			abort();
		}

		if (kcp->acklist != NULL) {
			size_t x;
			for (x = 0; x < kcp->ackcount; x++) {
				acklist[x * 2 + 0] = kcp->acklist[x * 2 + 0];
				acklist[x * 2 + 1] = kcp->acklist[x * 2 + 1];
			}
			ikcp_free(kcp->acklist);
		}

		kcp->acklist = acklist;
		kcp->ackblock = newblock;
	}

    ptr = &kcp->acklist[kcp->ackcount * 2];
	ptr[0] = sn;
	ptr[1] = ts;
	kcp->ackcount++;
}

static void ikcp_ack_get(const ikcpcb *kcp, int p, IUINT32 *sn, IUINT32 *ts)
{
	if (sn)
        *sn = kcp->acklist[p * 2 + 0];
	if (ts)
        *ts = kcp->acklist[p * 2 + 1];
}


//---------------------------------------------------------------------
// parse data
// 根据收到数据的sn，将它放到rcv_buf当中的合理位置，使得rcv_buf继续保持升序
// 然后，试着从rcv_buf移动数据到rcv_queue当中，
// 判断的标准一个是，rcv_queue中的元素个数尚未达到接受窗口的上限，
// 另一个标准是，rcv_queue中的元素的sn都是连续的，所以必须按照rcv_nxt从rcv_buf中拿数据
//
// 这里，我们额外对比下ikcp_parse_data和ikcp_recv.
// ikcp_parse_data将IKCPSEG插入到rcv_buf当中，然后试着从rcv_buf当中挪数据到rcv_queue
// 一种极端情况假设，就是它之后的数据包都没有丢，唯独头一个丢了，然后这个数据包重传刚一收到，
// 那当然得立马把rcv_buf中的一溜数据赶集往rcv_queue中送去啊
//
// ikcp_recv试着从rcv_queue中重组原始的数据包然后交给用户，
// 然后从rcv_buf中挪数据包过来
//
// 回味下ikcp_parse_data的作用：
// ikcp_parse_data将IKCPSEG插入到rcv_buf当中，然后试着从rcv_buf当中挪数据到rcv_queue
// 那么，我们思考下，IKCPSEG是从哪里来的? 
// 或者，换言之，就是肯定是在ikcp_parse_data之外还有一个函数，负责从UDP上获取数据，再经过某些处理之后，
// 然后才交给ikcp_parse_data，让它把数据包挂到rcv_buf这个链子中。
//
// 由ikcp_input调用
//
//---------------------------------------------------------------------
void ikcp_parse_data(ikcpcb *kcp, IKCPSEG *newseg)
{
	struct IQUEUEHEAD *p, *prev;
	IUINT32 sn = newseg->sn;
	int repeat = 0;

    // 正常收到的数据的sn应该在这样一个范围内：rcv_nxt <= sn < rcv_nxt + rcv_wnd
	if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) >= 0 ||
		_itimediff(sn, kcp->rcv_nxt) < 0) {
		ikcp_segment_delete(kcp, newseg);
		return;
	}

    // 请注意，不同于之前见到的，这里是从rcv_buf末尾，末尾开始的
    // 干什么呢，查找这个数据包在rcv_buf中的插入位置
    // 如果已经存在，没什么好说，直接释放这个结构
    // 如果不存在，就接着找到正确的插入位置，
    // 跳出这个循环时，p代表的seg的sn正好比我们的sn小，p之后的那个seg的sn正好比我们的sn大，
    // 扯了那么多，简而言之就是，我们应该将seg插入到p之后。
	for (p = kcp->rcv_buf.prev; p != &kcp->rcv_buf; p = prev) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		prev = p->prev;
		if (seg->sn == sn) {
			repeat = 1;
			break;
		}
		if (_itimediff(sn, seg->sn) > 0) {
			break;
		}
	}

	if (repeat == 0) {
		iqueue_init(&newseg->node);
                iqueue_add(&newseg->node, p);   // 将newseg插入到p之后
		kcp->nrcv_buf++;
	}	else {
		ikcp_segment_delete(kcp, newseg);
	}

#if 0
	ikcp_qprint("rcvbuf", &kcp->rcv_buf);
	printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

	// move available data from rcv_buf -> rcv_queue
	while (! iqueue_is_empty(&kcp->rcv_buf)) {
		IKCPSEG *seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
		if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
			iqueue_del(&seg->node);
			kcp->nrcv_buf--;
			iqueue_add_tail(&seg->node, &kcp->rcv_queue);
			kcp->nrcv_que++;
			kcp->rcv_nxt++;
		}	else {
			break;
		}
	}

#if 0
	ikcp_qprint("queue", &kcp->rcv_queue);
	printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

#if 1
//	printf("snd(buf=%d, queue=%d)\n", kcp->nsnd_buf, kcp->nsnd_que);
//	printf("rcv(buf=%d, queue=%d)\n", kcp->nrcv_buf, kcp->nrcv_que);
#endif
}


//---------------------------------------------------------------------
// input data
// 首先，需要明确一点的是，data指向的内存区域中包含的IKCPSEG以及其尾部的数据区域可能不止一个
// 每个IKCPSEG头结构的数据区域因为是变长的，所以必须先解析出IKCPSEG的头结构。
//---------------------------------------------------------------------
int ikcp_input(ikcpcb *kcp, const char *data, long size)
{
	IUINT32 una = kcp->snd_una;
	IUINT32 maxack = 0;
	int flag = 0;

	if (ikcp_canlog(kcp, IKCP_LOG_INPUT)) {
		ikcp_log(kcp, IKCP_LOG_INPUT, "[RI] %d bytes", size);
	}

    if (data == NULL || size < IKCP_OVERHEAD) return -1;

	while (1) {							//// 首先，需要明确一点的是，data指向的内存区域中包含的IKCPSEG以及其尾部的数据区域可能不止一个
		IUINT32 ts, sn, len, una, conv;
		IUINT16 wnd;
		IUINT8 cmd, frg;
		IKCPSEG *seg;

        /*
            IUINT32 conv;
            IUINT32 cmd;
            IUINT32 frg;
            IUINT32 wnd;
            IUINT32 ts;
            IUINT32 sn;
            IUINT32 una;
            IUINT32 len;

            IUINT32 resendts;
            IUINT32 rto;
            IUINT32 fastack;
            IUINT32 xmit;
         */

		if (size < (int)IKCP_OVERHEAD) break;

		data = ikcp_decode32u(data, &conv);
		if (conv != kcp->conv) return -1;

		data = ikcp_decode8u(data, &cmd);
		data = ikcp_decode8u(data, &frg);
		data = ikcp_decode16u(data, &wnd);

		data = ikcp_decode32u(data, &ts);
		data = ikcp_decode32u(data, &sn);

		data = ikcp_decode32u(data, &una);	// 搞清楚sn和una这两者之间的不同

		data = ikcp_decode32u(data, &len);

		size -= IKCP_OVERHEAD;

		if ((long)size < (long)len) return -2;

		if (cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
			cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS) 
			return -3;

		kcp->rmt_wnd = wnd;

        /*
         *  ikcp_input，首先，这个名字表明这个一个接受方向上的数据流动
         *  以我们常规的发送端、接收端为例，发送端向接收端发送数据，
         *  但是，不要忘了，接收端也会向发送端发送ACK。
         *  所以，我猜，ikcp_input也需要负责处理ACK。
         *  在TCP中，使用了累计ACK，在收到某个ACK sn之后，代表ack sn之前的数据包
         *  都已经收到了，那么在snd_buf中，对，就是snd_buf，本机的snd_buf就没有
         *  必要保留这个sn之前的任何数据包了，应该接收端都收到了嘛。
         *  那么这个ack sn，不正好就是我们snd_buf当中的una吗？
         *  所以IKCPSEG当中把ack sn取作una是有道理的
         *
         *  所以下面两步是，
         *  第一步呢，你对端不是说这个ack sn之前的数据包都收到了吗，那我根据这个sn清理下snd_buf
         *  第二步呢，我得重新设定下snd_buf中的una
         *
         *  插一句，这个ack sn也代表了对端下一步希望接收到的数据包的sn
         */
        ikcp_parse_una(kcp, una);
        ikcp_shrink_buf(kcp);

        /*
         *  data = ikcp_decode32u(data, &ts);
         *  rtt = _itimediff(kcp->current, ts);
         *  ikcp_update_ack(kcp, rtt);  // 更新rto
         *
         * 请注意现在是处理input
         *
         * 从一个接收方的角度来看，收到的数据主要是正常的数据包，
         * 以及发送数据包反馈回来的ack包。
         *
         * 另外，补充一下，一个数据包从发端送到收端，当中CMD总是不变的吧。
         * 以IKCP_PUSH_CMD为例，发送方觉得自己是push数据出去,
         * 但到了接收端，这个push的意味就不一样了
         *
         * 所以，同一个cmd，对于当时的发送接收双方，其意味也是不一样的
         *
         * A使用IKCP_CMD_PUSH向B发送数据包，B在接受到数据包之后，
         * 使用IKCP_CMD_ACK进行确认
         *
         *
         * IKCP_CMD_ACK:
         * 	更新rto
         * 	清理snd_buf以及更新sna
         * 	令maxack记录最大的sn
         *
         * IKCP_CMD_PUSH:
         *	首先说明下接受窗口的范围是：rcv_nxt <= sn < rcv_nxt + rcv_wnd
         *	越过右边界，是不被允许的，所以必须有sn < rcv_nxt + rcv_wnd；
         *	越过左边界是有可能的，但是这样的数据包，我们已经收到了，不再需要；
         *	但是我们仍然需要ack，一种解释是不是ack丢失，导致接收端明明收到了
         *	数据包，但是发送端还以为没收到，在重传
         *
         *
         */
		if (cmd == IKCP_CMD_ACK) {
            if (_itimediff(kcp->current, ts) >= 0)
				ikcp_update_ack(kcp, _itimediff(kcp->current, ts));

            ikcp_parse_ack(kcp, sn);	// 针对sn"单单"一个数据包进行ack
			ikcp_shrink_buf(kcp);

			if (flag == 0) {	// one-shot initialization
				flag = 1;
				maxack = sn;
			}	else {
				if (_itimediff(sn, maxack) > 0) {
					maxack = sn;
				}
			}
			if (ikcp_canlog(kcp, IKCP_LOG_IN_ACK)) {
                ikcp_log(kcp, IKCP_LOG_IN_DATA,
                         "input ack: sn=%lu rtt=%ld rto=%ld", sn,
                         (long) _itimediff(kcp->current, ts),
                         (long) kcp->rx_rto);
			}
		}
		else if (cmd == IKCP_CMD_PUSH) {
			if (ikcp_canlog(kcp, IKCP_LOG_IN_DATA)) {
                ikcp_log(kcp, IKCP_LOG_IN_DATA,
                         "input psh: sn=%lu ts=%lu", sn, ts);
			}
			if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) < 0) { // sn < rcv_nxt + rcv_wnd
				ikcp_ack_push(kcp, sn, ts);					// 添加到acklist中，看见没有，sn是需要进行ack的数据包的sn，
															// ts是需要进行ack的数据包的ts。
				if (_itimediff(sn, kcp->rcv_nxt) >= 0) {	// rcv_nxt <= sn < rcv_nxt + rcv_wnd
					seg = ikcp_segment_new(kcp, len);
					seg->conv = conv;
					seg->cmd = cmd;
					seg->frg = frg;
					seg->wnd = wnd;
					seg->ts = ts;
					seg->sn = sn;
					seg->una = una;
					seg->len = len;							// 注意是，这里需要复制一份数据，毕竟这部分数据是要挂在rcv_buf这个链中的

                    if (len > 0)
						memcpy(seg->data, data, len);		// 解析出IKCPSEG的头部结构，根据头部结构中的长度，复制相应长度的数据,构造一个IKCPSEG

					ikcp_parse_data(kcp, seg);
				}
			}
		}
		else if (cmd == IKCP_CMD_WASK) {
			// ready to send back IKCP_CMD_WINS in ikcp_flush
			// tell remote my window size
			kcp->probe |= IKCP_ASK_TELL;
			if (ikcp_canlog(kcp, IKCP_LOG_IN_PROBE)) {
				ikcp_log(kcp, IKCP_LOG_IN_PROBE, "input probe");
			}
		}
		else if (cmd == IKCP_CMD_WINS) {
			// do nothing
			if (ikcp_canlog(kcp, IKCP_LOG_IN_WINS)) {
				ikcp_log(kcp, IKCP_LOG_IN_WINS,
					"input wins: %lu", (IUINT32)(wnd));
			}
		}
		else {
			return -3;
		}

		data += len;
		size -= len;
	}

    if (flag != 0)							// 如果我们在前面的循环处理中遇到了一个ACK，
		ikcp_parse_fastack(kcp, maxack);    // 那么我们就给这个ACK SN之前的seg都计一次被跳过了。
                                            // 注意，如果上面的循环中处理了多个ACK，那么就按照最大的ack sn来处理，且就处理一次

	if (_itimediff(kcp->snd_una, una) > 0) {    //
		if (kcp->cwnd < kcp->rmt_wnd) {         // 拥塞窗口小于对端的窗口
			IUINT32 mss = kcp->mss;
			if (kcp->cwnd < kcp->ssthresh) {
				kcp->cwnd++;
				kcp->incr += mss;
			}	else {
				if (kcp->incr < mss) kcp->incr = mss;
				kcp->incr += (mss * mss) / kcp->incr + (mss / 16);
				if ((kcp->cwnd + 1) * mss <= kcp->incr) {
					kcp->cwnd++;
				}
			}
			if (kcp->cwnd > kcp->rmt_wnd) {
				kcp->cwnd = kcp->rmt_wnd;
				kcp->incr = kcp->rmt_wnd * mss;
			}
		}
	}

	return 0;
}


//---------------------------------------------------------------------
// ikcp_encode_seg
//---------------------------------------------------------------------
static char *ikcp_encode_seg(char *ptr, const IKCPSEG *seg)
{
	ptr = ikcp_encode32u(ptr, seg->conv);           // 4 bytes
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->cmd);     // 1 byte
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->frg);     // 1 byte
	ptr = ikcp_encode16u(ptr, (IUINT16)seg->wnd);   // 2 bytes
	ptr = ikcp_encode32u(ptr, seg->ts);             // 4 bytes
	ptr = ikcp_encode32u(ptr, seg->sn);             // 4 bytes
	ptr = ikcp_encode32u(ptr, seg->una);            // 4 bytes
	ptr = ikcp_encode32u(ptr, seg->len);            // 4 bytes
	return ptr;
}

// return kcp->rcv_wnd - kcp->nrcv_que;
static int ikcp_wnd_unused(const ikcpcb *kcp)
{
	if (kcp->nrcv_que < kcp->rcv_wnd)
		return kcp->rcv_wnd - kcp->nrcv_que;

	return 0;
}


//---------------------------------------------------------------------
// ikcp_flush
//---------------------------------------------------------------------
void ikcp_flush(ikcpcb *kcp)
{
	IUINT32 current = kcp->current;
	char *buffer = kcp->buffer;     // (kcp->mtu + IKCP_OVERHEAD) * 3
	char *ptr = buffer;
	int count, size, i;
	IUINT32 resent, cwnd;
	IUINT32 rtomin;
	struct IQUEUEHEAD *p;
	int change = 0;
	int lost = 0;
	IKCPSEG seg;

	// 'ikcp_update' haven't been called.
	// if (kcp->updated == 0) return;
    // NOTICE: controlled by frame ticker

    // 下面这些合起来就是IKCP_OVERHEAD这么大，ikcp_encode_seg就是将seg中的内容存入buffer当中
	seg.conv = kcp->conv;
	seg.cmd = IKCP_CMD_ACK;
	seg.frg = 0;
	seg.wnd = ikcp_wnd_unused(kcp); // kcp->rcv_wnd - kcp->nrcv_que !!
	seg.una = kcp->rcv_nxt;         // !!
	seg.len = 0;
	seg.sn = 0;
	seg.ts = 0;

	// flush ACKs
    // 这里主要完成的工作就是，将kcp->acklist中的{sn, ts}按上面的这种形式扩展，然后依次存入buffer当中
    // 当数量达到mtu时，将其发送
    // 此时cmd = IKCP_CMD_ACK;
	count = kcp->ackcount;
	for (i = 0; i < count; i++) {
		size = (int)(ptr - buffer); // size 代表已放置在buffer当中的数据量，IKCP_OVERHEAD 代表下一次将要放入的数据
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {    // 已经尽可能地填满MTU了
			ikcp_output(kcp, buffer, size);                 // ikcp_output紧接着调用我们提供的回调函数output_wrapper
			ptr = buffer;
		}
		ikcp_ack_get(kcp, i, &seg.sn, &seg.ts);
		ptr = ikcp_encode_seg(ptr, &seg);
	}

	kcp->ackcount = 0;

	// probe window size (if remote window size equals zero)
	if (kcp->rmt_wnd == 0) {
		if (kcp->probe_wait == 0) { // one-shot initialization
			kcp->probe_wait = IKCP_PROBE_INIT;  // 7000ms
			kcp->ts_probe = kcp->current + kcp->probe_wait;
		}
		else {
			if (_itimediff(kcp->current, kcp->ts_probe) >= 0) {
				if (kcp->probe_wait < IKCP_PROBE_INIT) 
					kcp->probe_wait = IKCP_PROBE_INIT;
				kcp->probe_wait += kcp->probe_wait / 2;
				if (kcp->probe_wait > IKCP_PROBE_LIMIT)
					kcp->probe_wait = IKCP_PROBE_LIMIT;
				kcp->ts_probe = kcp->current + kcp->probe_wait;
				kcp->probe |= IKCP_ASK_SEND;
			}
		}
	}	else {
		kcp->ts_probe = 0;
		kcp->probe_wait = 0;
	}

	// flush window probing commands
    // IKCP_CMD_WASK
	if (kcp->probe & IKCP_ASK_SEND) {
		seg.cmd = IKCP_CMD_WASK;
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ptr = ikcp_encode_seg(ptr, &seg);
	}

	// flush window probing commands
    // IKCP_CMD_WINS
	if (kcp->probe & IKCP_ASK_TELL) {
		seg.cmd = IKCP_CMD_WINS;
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ptr = ikcp_encode_seg(ptr, &seg);
	}

	kcp->probe = 0;

	// calculate window size
    // cwnd = min(kcp->snd_wnd, kcp->rmt_wnd, kcp->cwnd);
    // cwnd = min(kcp->snd_wnd, kcp->rmt_wnd); if (nocwnd)
	cwnd = _imin_(kcp->snd_wnd, kcp->rmt_wnd);
	if (kcp->nocwnd == 0) cwnd = _imin_(kcp->cwnd, cwnd);

	// move data from snd_queue to snd_buf
    // IKCP_CMD_PUSH
	while (_itimediff(kcp->snd_nxt, kcp->snd_una + cwnd) < 0) { // 发送窗口还未用完
		IKCPSEG *newseg;
		if (iqueue_is_empty(&kcp->snd_queue)) break;

		newseg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);

		iqueue_del(&newseg->node);
		iqueue_add_tail(&newseg->node, &kcp->snd_buf);
		kcp->nsnd_que--;
		kcp->nsnd_buf++;

		newseg->conv = kcp->conv;
		newseg->cmd = IKCP_CMD_PUSH;
		newseg->wnd = seg.wnd;  // ikcp_wnd_unused(kcp)
		newseg->ts = current;
		newseg->sn = kcp->snd_nxt++;
		newseg->una = kcp->rcv_nxt;
		newseg->resendts = current;
		newseg->rto = kcp->rx_rto;
		newseg->fastack = 0;
		newseg->xmit = 0;
	}

	// calculate resent
	resent = (kcp->fastresend > 0)? (IUINT32)kcp->fastresend : 0xffffffff;
	rtomin = (kcp->nodelay == 0)? (kcp->rx_rto >> 3) : 0;

	// flush data segments
    // 遍历snd_buf, 对于尚未发送过的或者是到了重传的时间点，将其添加到buffer当中，累计到mtu后发送
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
		IKCPSEG *segment = iqueue_entry(p, IKCPSEG, node);
		int needsend = 0;
		if (segment->xmit == 0) {   // xmit 应该是代表传输次数
			needsend = 1;
			segment->xmit++;
			segment->rto = kcp->rx_rto;
			segment->resendts = current + segment->rto + rtomin;
		}
		else if (_itimediff(current, segment->resendts) >= 0) {
			needsend = 1;
			segment->xmit++;
			kcp->xmit++;    // kcp->xmit保存重传次数？？
			if (kcp->nodelay == 0)
				segment->rto += kcp->rx_rto;    // rto翻倍
			else
				segment->rto += kcp->rx_rto / 2;
			segment->resendts = current + segment->rto;
			lost = 1;
		}
		else if (segment->fastack >= resent) {  // demo中resent被设置为2，fastack这个值实际上记录的是这个包被ack跳过的次数，
			needsend = 1;                       // 这样一来，就符合作者在github上所提到的当一个包被ack两次跳过之后，就立马重传
			segment->xmit++;                    // 而非等待超时
			segment->fastack = 0;
			segment->resendts = current + segment->rto;
			change++;
		}

		if (needsend) {
			int size, need;

			segment->ts = current;
			segment->wnd = seg.wnd;
			segment->una = kcp->rcv_nxt;

			size = (int)(ptr - buffer);
			need = IKCP_OVERHEAD + segment->len;

			if (size + need > (int)kcp->mtu) {
				ikcp_output(kcp, buffer, size);
				ptr = buffer;
			}

			ptr = ikcp_encode_seg(ptr, segment);

			if (segment->len > 0) {
				memcpy(ptr, segment->data, segment->len);
				ptr += segment->len;
			}

			if (segment->xmit >= kcp->dead_link)
				kcp->state = -1;
		}
	}

	// flush remain segments
	size = (int)(ptr - buffer);
	if (size > 0)
		ikcp_output(kcp, buffer, size);

	// update ssthresh
	if (change) {
		IUINT32 inflight = kcp->snd_nxt - kcp->snd_una;
		kcp->ssthresh = inflight / 2;
		if (kcp->ssthresh < IKCP_THRESH_MIN)
			kcp->ssthresh = IKCP_THRESH_MIN;
		kcp->cwnd = kcp->ssthresh + resent;
		kcp->incr = kcp->cwnd * kcp->mss;
	}

	if (lost) {
		kcp->ssthresh = cwnd / 2;
		if (kcp->ssthresh < IKCP_THRESH_MIN)
			kcp->ssthresh = IKCP_THRESH_MIN;
		kcp->cwnd = 1;
		kcp->incr = kcp->mss;
	}

	if (kcp->cwnd < 1) {
		kcp->cwnd = 1;
		kcp->incr = kcp->mss;
	}
}


//---------------------------------------------------------------------
// update state (call it repeatedly, every 10ms - 100ms),
// or you can ask ikcp_check when to call it again
// (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec.
//
// 第一次调用ikcp_update时，
// 将kcp->current置为current，kcp->ts_flush设置为相隔一个时间间隔，然后执行flush操作
//
// 之后调用ikcp_update时
// 将计划的flush时刻同现在的时刻求差
// 如果已经过了flush的时刻，那么就更新ts_flush，并立即flush
//
//---------------------------------------------------------------------
void ikcp_update(ikcpcb *kcp, IUINT32 current)
{
	IINT32 slap;

	kcp->current = current;

    // kcp->updated初始化为0,
    // kcp->ts_flush 初始化为IKCP_INTERVAL
    // one-shot initialization
	if (kcp->updated == 0) {
		kcp->updated = 1;
		kcp->ts_flush = kcp->current;
	}

	slap = _itimediff(kcp->current, kcp->ts_flush);

	if (slap >= 10000 || slap < -10000) {
		kcp->ts_flush = kcp->current;
		slap = 0;
	}

	if (slap >= 0) {
		kcp->ts_flush += kcp->interval;
        if (_itimediff(kcp->current, kcp->ts_flush) >= 0)
			kcp->ts_flush = kcp->current + kcp->interval;
		ikcp_flush(kcp);
	}
}


//---------------------------------------------------------------------
// Determine when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there 
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to 
// schedule ikcp_update (eg. implementing an epoll-like mechanism, 
// or optimize ikcp_update when handling massive kcp connections)
//---------------------------------------------------------------------
IUINT32 ikcp_check(const ikcpcb *kcp, IUINT32 current)
{
    // ts代表时间戳，tm代表时间差
	IUINT32 ts_flush = kcp->ts_flush;   // ts_flush代表应该进行flush的时刻
	IINT32 tm_flush = 0x7fffffff;       // tm_flush表示离预定的flush操作的时间差
	IINT32 tm_packet = 0x7fffffff;      // 离计划的最近的重传操作的时间差
	IUINT32 minimal = 0;
	struct IQUEUEHEAD *p;

	if (kcp->updated == 0)
		return current;

	if (_itimediff(current, ts_flush) >= 10000 ||
		_itimediff(current, ts_flush) < -10000)
		ts_flush = current;

    // 如果现在早就过了flush的时刻了，那就赶紧赶回（猜测）立马进行flush操作
	if (_itimediff(current, ts_flush) >= 0)
		return current;

    // 不然的话，tm_flush就是现在离计划flush时刻之间的时差
	tm_flush = _itimediff(ts_flush, current);

    // snd_buf中保存的是已经发送了但是还未收到ack的包
    // 毕竟是ARQ，这里的每个包都会被给予一个重传时间
    // 如果到时候，这包还在这个buf当中，就需要进行重传操作
    // 下面的代码就是计算现在时刻和最近的重传时刻之间的差值
    // 原则上肯定是从seqid最小的开始，以保证有序
    // 如果差值为负，那么就说明早该重传了，立马返回；
    // 可能会觉得直接以第一个包的差值返回就可以了，但是
    // 可能的情况是前面的包反复丢包、重传，使得其resendts远远大于后面的包
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		IINT32 diff = _itimediff(seg->resendts, current);
		if (diff <= 0)
			return current;
		if (diff < tm_packet) tm_packet = diff;
	}

    // minimal = min(tm_packet, tm_flush, kcp->interval);
	minimal = (IUINT32)(tm_packet < tm_flush ? tm_packet : tm_flush);
	if (minimal >= kcp->interval) minimal = kcp->interval;

	return current + minimal;
}



int ikcp_setmtu(ikcpcb *kcp, int mtu)
{
    if (mtu < 50 || mtu < (int) IKCP_OVERHEAD)
		return -1;

    char *buffer = (char *) ikcp_malloc((mtu + IKCP_OVERHEAD) * 3);   // mtu + IKCP_OVERHEAD ?? plus ??
    if (buffer == NULL)
		return -2;

    kcp->mtu = mtu;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	ikcp_free(kcp->buffer);
	kcp->buffer = buffer;

    return 0;
}

int ikcp_interval(ikcpcb *kcp, int interval)
{
	if (interval > 5000) interval = 5000;
	else if (interval < 10) interval = 10;
	kcp->interval = interval;
	return 0;
}

int ikcp_nodelay(ikcpcb *kcp, int nodelay, int interval, int resend, int nc)
{
	if (nodelay >= 0) {
		kcp->nodelay = nodelay;
        if (nodelay)
            kcp->rx_minrto = IKCP_RTO_NDL;
        else
			kcp->rx_minrto = IKCP_RTO_MIN;
    }

    if (interval >= 0) {
		if (interval > 5000) interval = 5000;
		else if (interval < 10) interval = 10;
		kcp->interval = interval;
	}

    if (resend >= 0)
		kcp->fastresend = resend;

    if (nc >= 0)
		kcp->nocwnd = nc;

    return 0;
}


int ikcp_wndsize(ikcpcb *kcp, int sndwnd, int rcvwnd)
{
	if (kcp) {
        if (sndwnd > 0)
			kcp->snd_wnd = sndwnd;
        if (rcvwnd > 0)
			kcp->rcv_wnd = rcvwnd;
	}
	return 0;
}

int ikcp_waitsnd(const ikcpcb *kcp)
{
	return kcp->nsnd_buf + kcp->nsnd_que;
}


// read conv
IUINT32 ikcp_getconv(const void *ptr)
{
	IUINT32 conv;
	ikcp_decode32u((const char*)ptr, &conv);
	return conv;
}
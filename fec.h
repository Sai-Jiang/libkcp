//
// Created by 理 傅 on 2017/1/2.
//

#ifndef KCP_FEC_H
#define KCP_FEC_H


#include <vector>
#include <stdint.h>
#include <memory>
#include "reedsolomon.h"

const size_t fecHeaderSize = 6; // sizeof(seqid) + sizeof(flag)
const size_t fecHeaderSizePlus2{fecHeaderSize + 2}; // 2 bytes used to indicate the actual data length
const uint16_t typeData = 0xf1;
const uint16_t typeFEC = 0xf2;
const int fecExpire = 30000;    // 30000ms

class fecPacket {
public:
    uint32_t seqid; // [4 bytes]
    uint16_t flag;  // [2 bytes] typeData or typeFEC
    row_type data;
    uint32_t ts;    //  4 bytes
};

class FEC {
public:
    FEC() = default;
    FEC(ReedSolomon enc) :enc(enc) {}

    static FEC New(int rxlimit, int dataShards, int parityShards);

    inline bool isEnabled() { return dataShards > 0 && parityShards > 0 ; }

    // 一个完整的调用链，应该是output_wrapper -> Encode --> Decode -> Input

    // 对应上面input操作的output，被作者组织在sess.h/sess.cpp中了
//    static int out_wrapper(const char *buf, int len, struct IKCPCB *kcp, void *user);

    // Calc Parity Shards
    // 给source symbol添加pad，然后送入FEC encoder中
    // 输出方向上的函数
    void Encode(std::vector<row_type> &shards);

    // Decode a raw array into fecPacket
    // 从网络上收到的裸字节流数据，将其解析封装成一个fecPacket
    // 输入方向的函数
    static fecPacket Decode(byte *data, size_t sz);

    // Input a FEC packet, and return recovered data if possible.
    // 译码还原丢失的数据包
    std::vector<row_type> Input(fecPacket &pkt);

    // Mark raw array as typeData, and write correct size.
    void MarkData(byte *data, uint16_t sz);

    // Mark raw array as typeFEC
    void MarkFEC(byte *data);
private:
    std::vector<fecPacket> rx; // ordered receive queue
    int rxlimit;
    int dataShards, parityShards, totalShards;
    uint32_t next{0}; // next used seqid
    ReedSolomon enc;
    uint32_t paws;  // Protect Against Wrapped Sequence numbers
    uint32_t lastCheck{0};
};


#endif //KCP_FEC_H

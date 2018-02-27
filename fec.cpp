//
// Created by 理 傅 on 2017/1/2.
//

#include <err.h>
#include <sys/time.h>
#include <iostream>
#include "fec.h"
#include "sess.h"
#include "encoding.h"

FEC
FEC::New(int rxlimit, int dataShards, int parityShards)  {
    if (dataShards <= 0 || parityShards <= 0) {
        throw std::invalid_argument("invalid arguments");
    }

    if (rxlimit < dataShards + parityShards) {
        throw std::invalid_argument("invalid arguments");
    }

    FEC fec(ReedSolomon::New(dataShards, parityShards));
    fec.rxlimit = rxlimit;
    fec.dataShards = dataShards;
    fec.parityShards = parityShards;
    fec.totalShards = dataShards + parityShards;
    fec.paws = (0xffffffff / uint32_t(fec.totalShards) - 1) * uint32_t(fec.totalShards);

    return fec;
}

// encapsulation
// sz => [seqid] [type flag] [data]

fecPacket
FEC::Decode(byte *data, size_t sz) {
    fecPacket pkt;
    data = decode32u(data, &pkt.seqid);     // 填充pkt.seqid
    data = decode16u(data, &pkt.flag);      // 填充pkt.flag
    pkt.data = std::make_shared<std::vector<byte>>(data, data + sz - fecHeaderSize);  // pkt.data
    struct timeval time;
    gettimeofday(&time, NULL);
    pkt.ts = uint32_t(time.tv_sec * 1000 + time.tv_usec / 1000);  // 填充pkt.ts
    return pkt;
}

/*
 * 参数sz代表的是实际的数据长度，不包含padding zeros
 * [seqid] [type tag] [ [len = 2 + length(data) ] [data] ]
 */
void
FEC::MarkData(byte *data, uint16_t sz) {
    data = encode32u(data, this->next++);              // this->next means "next seqid"
    data = encode16u(data, typeData);
    encode16u(data, static_cast<uint16_t>(sz + 2)); // including size itself
}

void
FEC::MarkFEC(byte *data) {
    data = encode32u(data,this->next++);
    encode16u(data,typeFEC);
    if (this->next >= this->paws) // paws would only occurs in MarkFEC
        this->next = 0;
}

/*
 * input的核心是一个接收队列，队列中保存的是fecPacket
 * 按照fecPacket seqid排序
 * std::vector<fecPacket> rx
 * fecPacket中的ts是在接受到这个packet之后加的，其作用呢，是起到一个expiration time的作用
 */

std::vector<row_type>
FEC::Input(fecPacket &pkt) {
    // row_type 或者 std::shared_ptr<std::vector<bytes>> 就代表一个symbol
    // std::vector<row_type> 这样就代表一组symbol，或者说是block
    std::vector<row_type> recovered;

    /*
     * wipe out expired fecPacket
     * 启用FEC会带来的一个问题就是说，接收到的fecPacket由于种种原因，没利用起来，堆积在那里
     * 这里就是定期处理这个问题
     */
    uint32_t now = currentMs();
    if (now - lastCheck >= fecExpire) {
        for (auto it = rx.begin(); it != rx.end();) {     // std::vector<fecPacket>
            if (now - it->ts > fecExpire)
                it = rx.erase(it);
            else
                it++;
        }
        lastCheck = now;
    }


    // 将fecPacket，按照seqid从小到大的顺序，插入到队列中
    // 注意队列中不存在seqid相同的元素
    auto n = rx.size() - 1;
    int insertIdx = 0;
    for (int i = n; i >= 0; i--) {
        if (pkt.seqid == rx[i].seqid) { // 请注意由于使用了ARQ，所以即便是fecPacket，也是有可能重复的，所以每个packet都会被赋予一个独立的seqid
            return recovered;   // return empty vector
        } else if (pkt.seqid > rx[i].seqid) {
            insertIdx = i + 1;
            break;
        }
    }
    // insert into ordered rx queue
    rx.insert(rx.begin() + insertIdx, pkt);

    // shard range for current packet
    auto shardBegin = pkt.seqid - pkt.seqid % totalShards;
    auto shardEnd = shardBegin + totalShards - 1;

    // max search range in ordered queue for current shard
    // 注意，实际情况中，由于网络的影响，searchBegin、searchEnd中
    // 会掺杂shardBegin、shardEnd范围之外的元素
    auto searchBegin = insertIdx - int(pkt.seqid % totalShards);
    searchBegin = searchBegin < 0 : 0, searchBegin;
    auto searchEnd = searchBegin + totalShards - 1;
    searchEnd = searchEnd >= rx.size() : rx.size() - 1, searchEnd;

    // 这里的逻辑是，我收到了一个fecPacket，那我得去看看这个fecPacket所在的block能不能decode了吧？
    // 利用systematic code的特性，解码成功的前提是至少有dataShards个packet，以避免不必要的检查操作
    if (searchEnd > searchBegin && searchEnd - searchBegin + 1 >= dataShards) {
        int numshard = 0;
        int numDataShard = 0;
        int first = 0;
        size_t maxlen = 0;

        std::vector<row_type> shardVec(totalShards);    // 数组中每个元素代表一个symbol，整体代表一个block
        std::vector<bool> shardflag(totalShards, false);

        for (auto i = searchBegin; i <= searchEnd; i++) {
            auto seqid = rx[i].seqid;
            if (seqid > shardEnd) {
                break;
            } else if (seqid >= shardBegin) {           // 对于满足shardBegin <= seqid <= shardEnd条件的，
                shardVec[seqid % totalShards] = rx[i].data;
                shardflag[seqid % totalShards] = true;
                numshard++;
                if (rx[i].flag == typeData)
                    numDataShard++;

                if (numshard == 1)
                    first = i;

                if (rx[i].data->size() > maxlen)       // 每个source symbol 并非等长
                    maxlen = rx[i].data->size();
            }
        }

        /*
         * FEC只会在发现有丢包发生时，才会进行译码还原，并将恢复出来的数据包交给kcp
         * 我们发送的逻辑是先发送source symbol，然后才是repair symbol
         * 如果网络是完美的，那么当block中的最有一个source symbol收到之后，我们就集齐了dataShards，
         * 不需要进行任何的恢复操作；
         * 如果
         */
        if (numDataShard == dataShards) { // no lost
            rx.erase(rx.begin() + first, rx.begin() + first + numshard);
        } else if (numshard >= dataShards) { // recoverable
            // equally resized
            for (int i = 0; i < shardVec.size(); i++) {
                if (shardVec[i] != nullptr) {
                    shardVec[i]->resize(maxlen, 0);
                }
            }

            // reconstruct shards
            enc.Reconstruct(shardVec);      // 这里才是重点，进行fec译码，尝试还原丢失的source symbol
            for (int k = 0; k < dataShards; k++) {
                if (!shardflag[k]) {
                    recovered.push_back(shardVec[k]);       // only here
                }
            }
            rx.erase(rx.begin() + first, rx.begin() + first + numshard);
        }
    }

    // std::vector<fecPacket> rx
    // input每次至多往队列中加一个元素
    // 如果加入的fecPacket导致队列的大小达到最大的上限，
    // 那么我们就将队列中的首个元素，seqid最小的fecPacket，
    // 也是最老的fecPacket清除掉
    // 默认值为 3个block大小
    if (rx.size() > rxlimit)
        rx.erase(rx.begin());

    return recovered;
}

// 计算repair symbol
// 所有的source symbol都pad到同等长度
// 对于block-based而言的FEC而言，padding只需要添加到这一组中的最长长度
// 而对于sliding window network coding这种情况而言，就必须pad到mtu大小
void FEC::Encode(std::vector<row_type> &shards) {
    // resize elements with 0 appending
    size_t max = 0;
    for (int i = 0; i < dataShards; i++) {
        if (shards[i]->size() > max)
            max = shards[i]->size();
    }

    for ( auto &s : shards) {
        if (s == nullptr)
            s = std::make_shared<std::vector<byte>>(max);
        else
            s->resize(max, 0);
    }

    enc.Encode(shards);
}

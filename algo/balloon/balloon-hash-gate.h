#ifndef BALLOON_GATE_H__
#define BALLOON_GATE_H__ 1

#include <stdint.h>

bool register_balloon_algo( algo_gate_t* gate);
int scanhash_balloon(struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr);
#endif

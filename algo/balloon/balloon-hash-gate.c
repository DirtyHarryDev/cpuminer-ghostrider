#include "algo-gate-api.h"
#include "balloon.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void alx_balloon(const void* input, void* output);

int scanhash_balloon(struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19] - 1;
   const uint32_t first_nonce = pdata[19];
   int thr_id = mythr->id;  // thr_id arg is deprecated

   uint32_t _ALIGN(32) hash32[8];
   uint32_t endiandata[32];

   for (int i=0; i < 19; i++)
        be32enc(&endiandata[i], pdata[i]);

   do {
        pdata[19] = ++n;
        be32enc(&endiandata[19], n);
        alx_balloon(endiandata, hash32);
        if (fulltest(hash32, ptarget)) {
            submit_solution( work, hash32, mythr );
        }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - first_nonce + 1;
    pdata[19] = n;
    return 0;
}

bool register_balloon_algo( algo_gate_t* gate )
{
  gate->optimizations = AES_OPT | SHA_OPT | AVX2_OPT | AVX512_OPT;
  gate->scanhash      = (void*)&scanhash_balloon;
  gate->hash          = (void*)&alx_balloon;
  return true;
};


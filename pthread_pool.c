#include "pthread_pool.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <search.h>

#define SIZEOFMW (sizeof(const size_t))
#define AND_MASK (SIZEOFMW - 1)
#define ARGSIZE_ADD(argsize) (SIZEOFMW - arg_size & AND_MASK)
int ptp_task_push_arg(struct ptp_task *ptask, const void *parg, size_t arg_size)
{
    int iret;
    unsigned char *pargs;
    if (sizeof(ptask->args) - ptask->args_size >= arg_size) {
        pargs = (unsigned char *)(ptask->args) + ptask->args_size;
        if (sizeof(uint64_t) == arg_size)
            *(uint64_t *) pargs = *(const uint64_t *)parg;
        else if (sizeof(uint32_t) == arg_size)
            *(uint32_t *) pargs = *(const uint32_t *)parg;
        else if (sizeof(uint16_t) == arg_size)
            *(uint16_t *) pargs = *(const uint16_t *)parg;
        else if (sizeof(uint8_t) == arg_size)
            *(uint8_t *) pargs = *(const uint8_t *)parg;
        else
            memcpy(pargs, parg, arg_size);
        ptask->args_size += arg_size + ARGSIZE_ADD(arg_size);
        iret = 0;
    } else
        iret = -1;
    return iret;
}

void ptp_task_pull_arg(void *parg, size_t arg_size, void **pargs)
{
    const void *const p = *pargs;
    *(const unsigned char **)pargs += arg_size + ARGSIZE_ADD(arg_size);
    if (sizeof(uint64_t) == arg_size)
        *(uint64_t *) parg = *(const uint64_t *)p;
    else if (sizeof(uint32_t) == arg_size)
        *(uint32_t *) parg = *(const uint32_t *)p;
    else if (sizeof(uint16_t) == arg_size)
        *(uint16_t *) parg = *(const uint16_t *)p;
    else if (sizeof(uint8_t) == arg_size)
        *(uint8_t *) parg = *(const uint8_t *)p;
    else
        memcpy(parg, p, arg_size);
}

#define NONREC_IDX ((const size_t)(-1))
void ptp_task_clear(struct ptp_task *ptask)
{
    ptask->task_fun_ptr = NULL;
    ptask->pnext = NULL;
    ptask->args_size = 0;
}

static void ptp_task_copy(struct ptp_task *pto, const struct ptp_task *pfrom)
{
    pto->task_fun_ptr = pfrom->task_fun_ptr;
    pto->args_size = pfrom->args_size;
    memcpy(pto->args, pfrom->args, pfrom->args_size);
    pto->task_pool_recursive_idx = pfrom->task_pool_recursive_idx;
}

/********************************
 * SINGLE ENDED QUEUE CONTAINER *
 *******************************/
struct common_queue_node_header {
    struct common_queue_node_header *pnext;
};
struct common_queue {
    struct common_queue_node_header *phead, *ptail;
    size_t size;
};
#define common_queue_empty(q) (0 == (q)->size)
static void zeroed_common_queue(struct common_queue *pqueue)
{
    pqueue->phead = NULL;
    pqueue->ptail = NULL;
    pqueue->size = 0;
}

static size_t common_queue_reduce_req(size_t req)
{
    if (0x4000 < req)
        req = 0x4000;
    return req;
}

void common_queue_pushback(struct common_queue *pqueue, struct common_queue_node_header *pnode)
{
    pnode->pnext = NULL;
    if (!common_queue_empty(pqueue))
        pqueue->ptail->pnext = pnode;
    else
        pqueue->phead = pnode;
    pqueue->ptail = pnode;
    pqueue->size++;
}

struct common_queue_node_header *common_queue_popfront(struct common_queue *pqueue)
{
    struct common_queue_node_header *const pret = pqueue->phead;
    if (!common_queue_empty(pqueue)) {
        pqueue->phead = pqueue->phead->pnext;
        pret->pnext = NULL;
        pqueue->size--;
        if (common_queue_empty(pqueue))
            pqueue->ptail = NULL;
    }
    return pret;
}

void common_queue_splice(struct common_queue *pqueue_to, struct common_queue *pqueue_from)
{
    if (!common_queue_empty(pqueue_from)) {
        if (!common_queue_empty(pqueue_to)) {
            pqueue_to->ptail->pnext = pqueue_from->phead;
            pqueue_to->size += pqueue_from->size;
            pqueue_to->ptail = pqueue_from->ptail;
        } else {                /*destination empty */
            pqueue_to->phead = pqueue_from->phead;
            pqueue_to->ptail = pqueue_from->ptail;
            pqueue_to->size = pqueue_from->size;
        }
        zeroed_common_queue(pqueue_from);
    }
}

int common_queue_free(struct common_queue *pqueue)
{
    int iret = 0;
    struct common_queue_node_header *pnode;
    do {
        pnode = common_queue_popfront(pqueue);
        free(pnode);
    } while (NULL != pnode);
    if (!common_queue_empty(pqueue))
        iret = -1;
    return iret;
}

int common_queue_realloc(struct common_queue *pqueue, size_t req, size_t size)
{
    size_t i;
    int iret = 0;
    struct common_queue_node_header *pnode;
    if (pqueue->size < req) {
        req -= pqueue->size;
        for (i = 0; i < req; ++i) {
            pnode = malloc(size);
            if (NULL != pnode)
                common_queue_pushback(pqueue, pnode);
            else {
                common_queue_free(pqueue);
                iret = -1;
                break;
            }
        }
    }
    return iret;
}

int common_queue_alloc(struct common_queue *pqueue, size_t req, size_t size)
{
    req = common_queue_reduce_req(req);
    zeroed_common_queue(pqueue);
    return common_queue_realloc(pqueue, req, size);
}

int common_queue_aralloc(struct common_queue *pqueue, size_t req, size_t size)
{
    size_t i;
    int iret = 0;
    unsigned char *ppt;
    struct common_queue_node_header *ptail;
    req = common_queue_reduce_req(req);
    if (req > 0) {
        pqueue->phead = ptail = ppt = malloc(req * size);
        if (NULL != ppt) {
            ppt += size;
            for (i = 1; i < req; ++i) {
                ptail->pnext = ppt;
                ptail = ppt;
                ppt += size;
            }
            ptail->pnext = NULL;
            pqueue->ptail = ptail;
            pqueue->size = req;
        } else
            iret = -1;
    } else
        zeroed_common_queue(pqueue);
    return iret;
}

int common_queue_arfree(struct common_queue *pqueue)
{
    int iret = 0;
    struct common_queue_node_header *pnode, *pminnode;
    pnode = pminnode = pqueue->phead;
    if (NULL != pnode) {
        do {
            pnode = pnode->pnext;
            if (NULL != pnode) {
                if (pnode < pminnode)
                    pminnode = pnode;
            } else
                break;
        } while (1);
        free(pminnode);
    }
    zeroed_common_queue(pqueue);
    return 0;
}

/**********************************************************
 * SINGLE ENDED QUEUE CONTAINER FOR TASKS FOR THREAD POOL *
 **********************************************************/
#define ptp_task_queue_alloc(q, r) \
    common_queue_alloc((struct ptp_task_queue *)(q), r, sizeof(const struct ptp_task))
#define ptp_task_queue_realloc(q, r) \
    common_queue_realloc((struct ptp_task_queue *)(q), r, sizeof(const struct ptp_task))
#define ptp_task_queue_free(q) common_queue_free(q)
#define ptp_task_queue_aralloc(q, r) \
    common_queue_aralloc((struct ptp_task_queue *)(q), r, sizeof(const struct ptp_task))
#define ptp_task_queue_arfree(q) common_queue_arfree(q)

#define ptp_task_queue_empty(q) common_queue_empty(q)
#define ptp_task_queue_pushback(q, n) \
    common_queue_pushback((struct ptp_task_queue *)(q), (struct ptp_task *)(n))
#define ptp_task_queue_popfront(q) \
    (struct ptp_task *)common_queue_popfront((struct ptp_task_queue *)(q))
#define ptp_task_queue_splice(qt, qf) common_queue_splice(qt, qf)

/***********************************************************
 * SINGLE ENDED QUEUE CONTAINER FOR ERRORS FOR THREAD POOL *
 ***********************************************************/
#define ptp_error_queue_alloc(q, r) \
    common_queue_alloc((struct ptp_error_queue *)(q), r, sizeof(const struct ptp_error))
#define ptp_error_queue_realloc(q, r) \
    common_queue_realloc((struct ptp_error_queue *)(q), r, sizeof(const struct ptp_error))
#define ptp_error_queue_free(q) common_queue_free(q)
#define ptp_error_queue_aralloc(q, r) \
    common_queue_aralloc((struct ptp_error_queue *)(q), r, sizeof(const struct ptp_error))
#define ptp_error_queue_arfree(q) common_queue_arfree(q)

#define ptp_error_queue_empty(q) common_queue_empty(q)
#define ptp_error_queue_pushback(q, n) \
    common_queue_pushback((struct ptp_error_queue *)(q), (struct ptp_error *)(n))
#define ptp_error_queue_popfront(q) \
    (struct ptp_error *)common_queue_popfront((struct ptp_error_queue *)(q))
#define ptp_error_queue_splice(qt, qf) common_queue_splice(qt, qf)

/**********************
 * THREAD POOL STATES *
 **********************/
#define PTP_STATE_WORKING 1
#define PTP_STATE_JOINING 2
#define PTP_STATE_TERMINATING 3
#define PTP_STATE_UNKNOW -1;

/***********************
 * THREAD POOL STATICS *
 ***********************/
static void ptp_error(struct pthread_pool *ptp)
{
    struct ptp_error *perr;
    pthread_mutex_lock(&(ptp->mtx_error));
    perr = ptp_error_queue_popfront(&(ptp->error_pool));
    if (NULL == perr)
        perr = ptp_error_queue_popfront(&(ptp->error_queue));
    perr->error = errno;
    perr->thread_id = pthread_self();
    ptp_error_queue_pushback(&(ptp->error_queue), perr);
    pthread_mutex_unlock(&(ptp->mtx_error));
    errno = 0;
}

static int pthread_t_cmp(const void *p1, const void *p2)
{
    const pthread_t *const pthread1 = (const pthread_t *)p1;
    const pthread_t *const pthread2 = (const pthread_t *)p2;
    const int iret = pthread_equal(*pthread1, *pthread2);
    return !iret;
}

static int ptp_init_attrs(pthread_attr_t * pthrdattr, pthread_mutexattr_t * pmutexattr,
                          pthread_condattr_t * pcondattr, pthread_barrierattr_t * pbrrattr)
{
    int iret, ithr, imtx, icnd, ibrr;
    ithr = pthread_attr_init(pthrdattr);
    imtx = pthread_mutexattr_init(pmutexattr);
    icnd = pthread_condattr_init(pcondattr);
    ibrr = pthread_barrierattr_init(pbrrattr);
    iret = ithr | imtx | icnd | ibrr;
    if (0 != iret) {
        if (0 == ithr)
            pthread_attr_destroy(pthrdattr);
        if (0 == imtx)
            pthread_mutexattr_destroy(pmutexattr);
        if (0 == icnd)
            pthread_condattr_destroy(pcondattr);
        if (0 == ibrr)
            pthread_barrierattr_destroy(pbrrattr);
    }
    return iret;
}

static int ptp_destroy_attrs(struct pthread_pool *ptp, pthread_attr_t * pthrdattr,
                             pthread_mutexattr_t * pmutexattr, pthread_condattr_t * pcondattr,
                             pthread_barrierattr_t * pbrrattr)
{
    int iret, ithr, imtx, icnd, ibrr;
    ithr = pthread_attr_destroy(pthrdattr);
    imtx = pthread_mutexattr_destroy(pmutexattr);
    icnd = pthread_condattr_destroy(pcondattr);
    ibrr = pthread_barrierattr_destroy(pbrrattr);
    iret = ithr | imtx | icnd | ibrr;
    return iret;
}

static void pthread_cond_wait_with_err(struct pthread_pool *ptp, pthread_cond_t * pcv,
                                       pthread_mutex_t * pmtx)
{
    const int iret = pthread_cond_wait(pcv, pmtx);
    if (0 != iret) {
        errno = iret;
        ptp_error(ptp);
    }
}

static int pthread_mutex_lock_with_err(struct pthread_pool *ptp, pthread_mutex_t * pmtx)
{
    const int iret = pthread_mutex_lock(pmtx);
    if (0 != iret) {
        errno = iret;
        ptp_error(ptp);
    }
    return iret;
}

static int pthread_barrier_wait_with_err(struct pthread_pool *ptp)
{
    int iret;
    size_t br;
    do {
        __atomic_load(&(ptp->join_barrier), &br, __ATOMIC_ACQUIRE);
        if (0 != br) {
            __atomic_fetch_sub(&(ptp->join_barrier), 1, __ATOMIC_RELEASE);
            iret = pthread_barrier_wait(&(ptp->brr_jointasks_occurred));
            if (0 != iret && PTHREAD_BARRIER_SERIAL_THREAD != iret) {
                errno = iret;
                ptp_error(ptp);
            }
        } else
            break;
    } while (1);
    return iret;
}

static void *ptp_thread_routine(void *arg)
{
    size_t new_pool_size, br;
    int iret = 0, state, need_signal;
    struct ptp_task *ptask, task;
    struct pthread_pool *const ptp = (struct pthread_pool *)arg;
    pthread_mutex_t *const pmtx_pool = &(ptp->mtx_pool);
    pthread_mutex_t *const pmtx_queue = &(ptp->mtx_queue);
    pthread_mutex_t *const pmtx_pool_rec = &(ptp->mtx_pool_recursive);
    pthread_mutex_t *const pmtx_queue_rec = &(ptp->mtx_queue_recursive);
    sem_t *psem;
    do {
        if (0 == pthread_mutex_lock_with_err(ptp, pmtx_queue_rec)) {
            ptask = ptp_task_queue_popfront(&(ptp->task_queue_recursive));
            pthread_mutex_unlock(pmtx_queue_rec);
        }

        if (NULL == ptask) {
            if (0 == pthread_mutex_lock_with_err(ptp, pmtx_queue)) {
                ptask = ptp_task_queue_popfront(&(ptp->task_queue));
                pthread_mutex_unlock(pmtx_queue);
            }
        }

        if (NULL != ptask) {
            ptp_task_copy(&task, ptask);
            if (NONREC_IDX == task.task_pool_recursive_idx) {
                if (0 == pthread_mutex_lock_with_err(ptp, pmtx_pool)) {
                    ptp_task_queue_pushback(&(ptp->task_pool), ptask);
                    new_pool_size = ptp->task_pool.size;
                    pthread_mutex_unlock(pmtx_pool);
                    if (1 == new_pool_size)     /*was 0 before pushback */
                        pthread_cond_broadcast(&(ptp->cnd_freetask_occurred));
                }
            } else {
                if (0 == pthread_mutex_lock_with_err(ptp, pmtx_pool_rec)) {
                    ptp_task_queue_pushback(&(ptp->task_pool_recursive), ptask);
                    pthread_mutex_unlock(pmtx_pool_rec);
                    psem = ptp->ptr_sems_recursive + task.task_pool_recursive_idx;
                    if (0 != sem_post(psem))
                        ptp_error(ptp);
                }
            }

            task.task_fun_ptr(task.args);
        } else {                /*NULL == ptask */
            __atomic_load(&(ptp->state), &state, __ATOMIC_ACQUIRE);

            if (PTP_STATE_TERMINATING == state) {
                pthread_barrier_wait_with_err(ptp);
                break;
            } else if (PTP_STATE_JOINING == state) {
                pthread_cond_broadcast(&(ptp->cnd_jointasks_occurred));
                pthread_barrier_wait_with_err(ptp);
            } else {            /*TT_TP_STATE_WORKING == state */
                if (0 == pthread_mutex_lock_with_err(ptp, pmtx_queue)) {
                    while (0 == ptp->task_queue.size) {
                        __atomic_load(&(ptp->state), &state, __ATOMIC_ACQUIRE);
                        if (PTP_STATE_WORKING != state)
                            break;

                        if (0 != ptp->task_queue.size)
                            break;

                        pthread_cond_wait_with_err(ptp, &(ptp->cnd_hottask_occurred), pmtx_queue);
                    }
                    pthread_mutex_unlock(pmtx_queue);
                }
            }
        }
    } while (1);

    return arg;
}

/***************
 * THREAD POOL *
 ***************/
#define MTX_POOL_INITIATED 0
#define MTX_QUEUE_INITIATED 1
#define MTX_POOL_REC_INITIATED 2
#define MTX_QUEUE_REC_INITIATED 3
#define MTX_ERROR_INITIATED 4
#define CND_HOTTASK_INITIATED 5
#define CND_FREETASK_INITIATED 6
#define CND_JOINTASKS_INITIATED 7
#define BRR_JOINTASKS_INITIATED 8
#define TASK_POOL_ALLOCATED 9
#define TASK_QUEUE_ALLOCATED 10
#define TASK_POOL_REC_ARALLOCATED 11
#define TASK_QUEUE_REC_ARALLOCATED 12
#define ERROR_POOL_ARALLOCATED 13
#define ERROR_QUEUE_ARALLOCATED 14
#define THREADS_ALLOCATED 15
#define SEMAPHORES_ALLOCATED 16
#define THREADS_INITIATED 17
#define SEMAPHORES_INITIATED 18
#define MAX_INITS 19

int pthread_pool_alloc(struct pthread_pool *ptp, size_t num_of_threads)
{
    size_t i;
    const size_t task_pool_size = 5000;
    char thread_name[16];
    int iret, numCPU;
    pthread_attr_t thrdattr;
    pthread_mutexattr_t mutexattr;
    pthread_condattr_t condattr;
    pthread_barrierattr_t brrattr;

    memset(ptp, 0, sizeof(*ptp));
    iret = ptp_init_attrs(&thrdattr, &mutexattr, &condattr, &brrattr);
    if (0 == iret) {
        numCPU = get_nprocs();
        if (numCPU < 1)
            numCPU = 1;
        if ((size_t)numCPU < num_of_threads)
            num_of_threads = (size_t)numCPU;
        if (num_of_threads < 4)
            num_of_threads = 4;

        ptp->flags = 0;
        if (0 == pthread_mutex_init(&(ptp->mtx_pool), &mutexattr))
            ptp->flags |= (0x00000001 << MTX_POOL_INITIATED);
        if (0 == pthread_mutex_init(&(ptp->mtx_queue), &mutexattr))
            ptp->flags |= (0x00000001 << MTX_QUEUE_INITIATED);
        if (0 == pthread_mutex_init(&(ptp->mtx_pool_recursive), &mutexattr))
            ptp->flags |= (0x00000001 << MTX_POOL_REC_INITIATED);
        if (0 == pthread_mutex_init(&(ptp->mtx_queue_recursive), &mutexattr))
            ptp->flags |= (0x00000001 << MTX_QUEUE_REC_INITIATED);
        if (0 == pthread_mutex_init(&(ptp->mtx_error), &mutexattr))
            ptp->flags |= (0x00000001 << MTX_ERROR_INITIATED);
        if (0 == pthread_cond_init(&(ptp->cnd_hottask_occurred), &condattr))
            ptp->flags |= (0x00000001 << CND_HOTTASK_INITIATED);
        if (0 == pthread_cond_init(&(ptp->cnd_freetask_occurred), &condattr))
            ptp->flags |= (0x00000001 << CND_FREETASK_INITIATED);
        if (0 == pthread_cond_init(&(ptp->cnd_jointasks_occurred), &condattr))
            ptp->flags |= (0x00000001 << CND_JOINTASKS_INITIATED);
        if (0 == pthread_barrier_init(&(ptp->brr_jointasks_occurred), &brrattr, num_of_threads))
            ptp->flags |= (0x00000001 << BRR_JOINTASKS_INITIATED);
        if (0 == ptp_task_queue_alloc(&(ptp->task_pool), task_pool_size))
            ptp->flags |= (0x00000001 << TASK_POOL_ALLOCATED);
        if (0 == ptp_task_queue_alloc(&(ptp->task_queue), 0))
            ptp->flags |= (0x00000001 << TASK_QUEUE_ALLOCATED);

        ptp->task_pool_size = task_pool_size;
        ptp->state = PTP_STATE_WORKING;
        ptp->join_barrier = 0;
        ptp->num_of_threads = num_of_threads;
        if (0 ==
            ptp_task_queue_aralloc(&(ptp->task_pool_recursive), MAX_REC_CALLS * num_of_threads))
            ptp->flags |= (0x00000001 << TASK_POOL_REC_ARALLOCATED);
        if (0 == ptp_task_queue_aralloc(&(ptp->task_queue_recursive), 0))
            ptp->flags |= (0x00000001 << TASK_QUEUE_REC_ARALLOCATED);
        if (0 == ptp_error_queue_aralloc(&(ptp->error_pool), MAX_ERROR_POOL))
            ptp->flags |= (0x00000001 << ERROR_POOL_ARALLOCATED);
        if (0 == ptp_error_queue_aralloc(&(ptp->error_queue), 0))
            ptp->flags |= (0x00000001 << ERROR_QUEUE_ARALLOCATED);

        ptp->ptr_threads = malloc(ptp->num_of_threads * sizeof(ptp->ptr_threads[0]));
        if (NULL != ptp->ptr_threads) {
            memset(ptp->ptr_threads, 0, ptp->num_of_threads * sizeof(ptp->ptr_threads[0]));
            ptp->flags |= (0x00000001 << THREADS_ALLOCATED);
        }
        ptp->ptr_sems_recursive = malloc(ptp->num_of_threads * sizeof(ptp->ptr_sems_recursive[0]));
        if (NULL != ptp->ptr_threads) {
            memset(ptp->ptr_sems_recursive, 0,
                   ptp->num_of_threads * sizeof(ptp->ptr_sems_recursive[0]));
            ptp->flags |= (0x00000001 << SEMAPHORES_ALLOCATED);
        }

        for (i = 0; i < ptp->num_of_threads; ++i) {
            if (0 != sem_init(ptp->ptr_sems_recursive + i, 0, MAX_REC_CALLS)) {
                ptp->num_of_threads = i;
                break;
            }
            if (0 == pthread_create(ptp->ptr_threads + i, &thrdattr, ptp_thread_routine, ptp)) {
                sprintf(thread_name, "PTP %zu", i + 1);
                pthread_setname_np(ptp->ptr_threads[i], thread_name);
            } else {
                sem_destroy(ptp->ptr_sems_recursive + i);       /*destroy last semaphore */
                ptp->num_of_threads = i;
                break;
            }
        }
        if (ptp->num_of_threads == num_of_threads) {
            ptp->flags |= (0x00000001 << THREADS_INITIATED);
            ptp->flags |= (0x00000001 << SEMAPHORES_INITIATED);
        }

        iret = ptp_destroy_attrs(ptp, &thrdattr, &mutexattr, &condattr, &brrattr);
        if (ptp->flags != (0x00000001 << MAX_INITS) - 1) {
            pthread_pool_free(ptp);
            iret = -1;
        }
    }
    return iret;
}

int pthread_pool_free(struct pthread_pool *ptp)
{
    size_t i;
    int iret = 0, ii;
    const uint32_t state = PTP_STATE_TERMINATING;

    if (ptp->flags == (0x00000001 << MAX_INITS) - 1) {
        iret = pthread_pool_joinall_tasks(ptp);
        __atomic_store(&(ptp->state), &state, __ATOMIC_RELEASE);

        /*mtx_queue must be acquired to avoid deadlocks
         * on waiting hottask in thread routine*/
        pthread_mutex_lock(&(ptp->mtx_queue));
        pthread_cond_broadcast(&(ptp->cnd_hottask_occurred));
        pthread_mutex_unlock(&(ptp->mtx_queue));
    }

    ii = 0;
    for (i = 0; i < ptp->num_of_threads; ++i) {
        if (0 != pthread_join(ptp->ptr_threads[i], NULL))
            ii = -1;
        if (0 != sem_destroy(ptp->ptr_sems_recursive + i))
            ii = -1;
    }

    if (0 == ii) {
        ptp->flags &= ~(0x00000001 << THREADS_INITIATED);
        ptp->flags &= ~(0x00000001 << SEMAPHORES_INITIATED);
    } else
        iret |= ii;

    if (ptp->flags & (0x00000001 << THREADS_ALLOCATED)) {
        free(ptp->ptr_threads);
        ptp->flags &= ~(0x00000001 << THREADS_ALLOCATED);
    }
    if (ptp->flags & (0x00000001 << SEMAPHORES_ALLOCATED)) {
        free(ptp->ptr_sems_recursive);
        ptp->flags &= ~(0x00000001 << SEMAPHORES_ALLOCATED);
    }

    if (ptp->flags & (0x00000001 << MTX_POOL_INITIATED)) {
        pthread_mutex_destroy(&(ptp->mtx_pool));
        ptp->flags &= ~(0x00000001 << MTX_POOL_INITIATED);
    }
    if (ptp->flags & (0x00000001 << MTX_QUEUE_INITIATED)) {
        pthread_mutex_destroy(&(ptp->mtx_queue));
        ptp->flags &= ~(0x00000001 << MTX_QUEUE_INITIATED);
    }
    if (ptp->flags & (0x00000001 << MTX_POOL_REC_INITIATED)) {
        pthread_mutex_destroy(&(ptp->mtx_pool_recursive));
        ptp->flags &= ~(0x00000001 << MTX_POOL_REC_INITIATED);
    }
    if (ptp->flags & (0x00000001 << MTX_QUEUE_REC_INITIATED)) {
        pthread_mutex_destroy(&(ptp->mtx_queue_recursive));
        ptp->flags &= ~(0x00000001 << MTX_QUEUE_REC_INITIATED);
    }
    if (ptp->flags & (0x00000001 << MTX_ERROR_INITIATED)) {
        pthread_mutex_destroy(&(ptp->mtx_error));
        ptp->flags &= ~(0x00000001 << MTX_ERROR_INITIATED);
    }
    if (ptp->flags & (0x00000001 << CND_HOTTASK_INITIATED)) {
        pthread_cond_destroy(&(ptp->cnd_hottask_occurred));
        ptp->flags &= ~(0x00000001 << CND_HOTTASK_INITIATED);
    }
    if (ptp->flags & (0x00000001 << CND_FREETASK_INITIATED)) {
        pthread_cond_destroy(&(ptp->cnd_freetask_occurred));
        ptp->flags &= ~(0x00000001 << CND_FREETASK_INITIATED);
    }
    if (ptp->flags & (0x00000001 << CND_JOINTASKS_INITIATED)) {
        pthread_cond_destroy(&(ptp->cnd_jointasks_occurred));
        ptp->flags &= ~(0x00000001 << CND_JOINTASKS_INITIATED);
    }
    if (ptp->flags & (0x00000001 << BRR_JOINTASKS_INITIATED)) {
        pthread_barrier_destroy(&(ptp->brr_jointasks_occurred));
        ptp->flags &= ~(0x00000001 << BRR_JOINTASKS_INITIATED);
    }
    if (ptp->flags & (0x00000001 << TASK_POOL_ALLOCATED)) {
        ptp_task_queue_free(&(ptp->task_pool));
        ptp->flags &= ~(0x00000001 << TASK_POOL_ALLOCATED);
    }
    if (ptp->flags & (0x00000001 << TASK_QUEUE_ALLOCATED)) {
        ptp_task_queue_free(&(ptp->task_queue));
        ptp->flags &= ~(0x00000001 << TASK_QUEUE_ALLOCATED);
    }

    ptp_task_queue_splice(&(ptp->task_pool_recursive), &(ptp->task_queue_recursive));
    if (ptp->flags & (0x00000001 << TASK_POOL_REC_ARALLOCATED)) {
        ptp_task_queue_arfree(&(ptp->task_pool_recursive));
        ptp->flags &= ~(0x00000001 << TASK_POOL_REC_ARALLOCATED);
    }
    if (ptp->flags & (0x00000001 << TASK_QUEUE_REC_ARALLOCATED)) {
        ptp_task_queue_arfree(&(ptp->task_queue_recursive));
        ptp->flags &= ~(0x00000001 << TASK_QUEUE_REC_ARALLOCATED);
    }

    ptp_error_queue_splice(&(ptp->error_pool), &(ptp->error_queue));
    if (ptp->flags & (0x00000001 << ERROR_POOL_ARALLOCATED)) {
        ptp_error_queue_arfree(&(ptp->error_pool));
        ptp->flags &= ~(0x00000001 << ERROR_POOL_ARALLOCATED);
    }
    if (ptp->flags & (0x00000001 << ERROR_QUEUE_ARALLOCATED)) {
        ptp_error_queue_arfree(&(ptp->error_queue));
        ptp->flags &= ~(0x00000001 << ERROR_QUEUE_ARALLOCATED);
    }

    if (0 != ptp->flags)
        iret = -1;
    memset(ptp, 0, sizeof(*ptp));
    return iret;
}

/*Obtain new task to fill and execute in TP.
Can be blocks calling thread until task_pool empty*/
struct ptp_task *pthread_pool_balloc_task(struct pthread_pool *ptp)
{
    uint32_t state;
    struct ptp_task *ptask;
    pthread_t cur_thread, *pthrd;
    size_t cur_thread_idx, num_of_threads;
    sem_t *cur_thread_sem;

    __atomic_load(&(ptp->state), &state, __ATOMIC_ACQUIRE);
    cur_thread = pthread_self();
    num_of_threads = ptp->num_of_threads;
    pthrd =
        lfind(&cur_thread, ptp->ptr_threads, &num_of_threads, sizeof(ptp->ptr_threads[0]),
              pthread_t_cmp);

    if (PTP_STATE_WORKING == state || PTP_STATE_JOINING == state
        || (PTP_STATE_TERMINATING == state && NULL != pthrd)) {
        if (NULL != pthrd) {    /*this thread is one of thread_pool */
            cur_thread_idx = pthrd - ptp->ptr_threads;
            cur_thread_sem = ptp->ptr_sems_recursive + cur_thread_idx;
            if (0 == sem_wait(cur_thread_sem)) {
                if (0 == pthread_mutex_lock(&(ptp->mtx_pool_recursive))) {
                    ptask = ptp_task_queue_popfront(&(ptp->task_pool_recursive));
                    pthread_mutex_unlock(&(ptp->mtx_pool_recursive));
                    ptp_task_clear(ptask);
                    ptask->task_pool_recursive_idx = cur_thread_idx;
                } else {
                    ptp_error(ptp);
                    ptask = NULL;
                    sem_post(cur_thread_sem);
                }
            } else {
                ptp_error(ptp);
                ptask = NULL;
            }
        } else if (0 == pthread_mutex_lock(&(ptp->mtx_pool))) {
            while (0 == ptp->task_pool.size)
                pthread_cond_wait_with_err(ptp, &(ptp->cnd_freetask_occurred), &(ptp->mtx_pool));
            ptask = ptp_task_queue_popfront(&(ptp->task_pool));
            pthread_mutex_unlock(&(ptp->mtx_pool));

            if (NULL != ptask) {
                ptp_task_clear(ptask);
                ptask->task_pool_recursive_idx = NONREC_IDX;
            }
        } else {
            ptp_error(ptp);
            ptask = NULL;
        }
    } else
        ptask = NULL;

    return ptask;
}

/*Obtain new task to fill and execute in TP.
Never blocks calling thread. If task_pool not empty,
task obtain from task_pool. If task_pool empty and opt == 0,
returns NULL, if task_pool empty and opt != 0, returns new task*/
struct ptp_task *pthread_pool_nballoc_task(struct pthread_pool *ptp, int opt)
{
    int iret, i, state;
    pthread_t cur_thread, *pthrd;
    size_t num_of_threads, cur_thread_idx;
    sem_t *cur_thread_sem;
    struct ptp_task *ptask = NULL;

    cur_thread = pthread_self();
    num_of_threads = ptp->num_of_threads;
    pthrd =
        lfind(&cur_thread, ptp->ptr_threads, &num_of_threads, sizeof(ptp->ptr_threads[0]),
              pthread_t_cmp);

    for (i = 0; i < 15; ++i) {
        __atomic_load(&(ptp->state), &state, __ATOMIC_ACQUIRE);
        if (PTP_STATE_WORKING == state || PTP_STATE_JOINING == state
            || (PTP_STATE_TERMINATING == state && NULL != pthrd)) {

            if (NULL != pthrd) {        /*this thread is one of thread_pool */
                cur_thread_idx = pthrd - ptp->ptr_threads;
                cur_thread_sem = ptp->ptr_sems_recursive + cur_thread_idx;
                if (0 == sem_trywait(cur_thread_sem)) {
                    if (0 == pthread_mutex_lock(&(ptp->mtx_pool_recursive))) {
                        ptask = ptp_task_queue_popfront(&(ptp->task_pool_recursive));
                        pthread_mutex_unlock(&(ptp->mtx_pool_recursive));
                        ptp_task_clear(ptask);
                        ptask->task_pool_recursive_idx = cur_thread_idx;
                        break;
                    } else {
                        ptp_error(ptp);
                        ptask = NULL;
                        sem_post(cur_thread_sem);
                    }
                } else {
                    if (EAGAIN != errno) {
                        ptp_error(ptp);
                        ptask = NULL;
                        break;
                    }
                }
            }

            iret = pthread_mutex_trylock(&(ptp->mtx_pool));
            if (0 == iret) {
                ptask = ptp_task_queue_popfront(&(ptp->task_pool));
                pthread_mutex_unlock(&(ptp->mtx_pool));
            } else {
                if (EBUSY != iret && EAGAIN != iret) {
                    ptp_error(ptp);
                    ptask = NULL;
                    break;
                }
            }

            if (NULL != ptask) {
                ptp_task_clear(ptask);
                ptask->task_pool_recursive_idx = NONREC_IDX;
                break;
            } else
                sched_yield();
        } else
            break;
    }

    if (NULL == ptask && 0 != opt) {
        ptask = malloc(sizeof(*ptask));
        if (NULL != ptask) {
            __atomic_fetch_add(&(ptp->task_pool_size), 1, __ATOMIC_RELEASE);
            ptp_task_clear(ptask);
            ptask->task_pool_recursive_idx = NONREC_IDX;
        }
    }

    return ptask;
}

int pthread_pool_add_task(struct pthread_pool *ptp, struct ptp_task *ptask)
{
    int iret, state;
    size_t queue_size;

    __atomic_load(&(ptp->state), &state, __ATOMIC_ACQUIRE);
    if (PTP_STATE_WORKING == state || PTP_STATE_JOINING == state
        || (PTP_STATE_TERMINATING == state && NONREC_IDX != ptask->task_pool_recursive_idx)) {
        if (NONREC_IDX == ptask->task_pool_recursive_idx) {
            iret = pthread_mutex_lock_with_err(ptp, &(ptp->mtx_queue));
            if (0 == iret) {
                ptp_task_queue_pushback(&(ptp->task_queue), ptask);
                queue_size = ptp->task_queue.size;
                pthread_mutex_unlock(&(ptp->mtx_queue));
                if (1 == queue_size)    /*queue was empty */
                    pthread_cond_signal(&(ptp->cnd_hottask_occurred));
            }
        } else {
            iret = pthread_mutex_lock_with_err(ptp, &(ptp->mtx_queue_recursive));
            if (0 == iret) {
                ptp_task_queue_pushback(&(ptp->task_queue_recursive), ptask);
                queue_size = ptp->task_queue_recursive.size;
                pthread_mutex_unlock(&(ptp->mtx_queue_recursive));
                if (1 == queue_size)    /*queue was empty */
                    pthread_cond_signal(&(ptp->cnd_hottask_occurred));
            }
        }
    } else
        iret = -1;
    return iret;
}

int pthread_pool_removeall_tasks(struct pthread_pool *ptp)
{
    struct ptp_task_queue buf_queue;
    const int iret = ptp_task_queue_alloc(&buf_queue, 0);
    if (0 == iret) {
        /*make it separately to avoid deadlocks */
        if (0 == pthread_mutex_lock_with_err(ptp, &(ptp->mtx_queue))) {
            ptp_task_queue_splice(&buf_queue, &(ptp->task_queue));
            pthread_mutex_unlock(&(ptp->mtx_queue));
        }

        if (0 == pthread_mutex_lock_with_err(ptp, &(ptp->mtx_pool))) {
            ptp_task_queue_splice(&(ptp->task_pool), &buf_queue);
            pthread_mutex_unlock(&(ptp->mtx_pool));
        }
    }
    return iret;
}

int pthread_pool_joinall_tasks(struct pthread_pool *ptp)
{
    int iret, state;
    size_t task_pool_size;
    const uint32_t state_joining = PTP_STATE_JOINING;
    const uint32_t state_working = PTP_STATE_WORKING;
    __atomic_load(&(ptp->state), &state, __ATOMIC_ACQUIRE);
    if (PTP_STATE_WORKING == state) {
        __atomic_store(&(ptp->state), &state_joining, __ATOMIC_RELEASE);

        __atomic_fetch_add(&(ptp->join_barrier), ptp->num_of_threads, __ATOMIC_RELEASE);

        if (0 == pthread_mutex_lock_with_err(ptp, &(ptp->mtx_pool_recursive))) {
            while (MAX_REC_CALLS * ptp->num_of_threads != ptp->task_pool_recursive.size)
                pthread_cond_wait_with_err(ptp, &(ptp->cnd_jointasks_occurred),
                                           &(ptp->mtx_pool_recursive));
            pthread_mutex_unlock(&(ptp->mtx_pool_recursive));
        }

        if (0 == pthread_mutex_lock_with_err(ptp, &(ptp->mtx_pool))) {
            do {
                __atomic_load(&(ptp->task_pool_size), &task_pool_size, __ATOMIC_ACQUIRE);
                if (task_pool_size != ptp->task_pool.size)
                    pthread_cond_wait_with_err(ptp, &(ptp->cnd_jointasks_occurred),
                                               &(ptp->mtx_pool));
                else
                    break;
            } while (1);
            pthread_mutex_unlock(&(ptp->mtx_pool));
        }

        __atomic_store(&(ptp->state), &state_working, __ATOMIC_RELEASE);
        iret = 0;
    } else
        iret = -1;
    return iret;
}

size_t pthread_pool_task_pool_size(struct pthread_pool *ptp)
{
    size_t task_pool_size;
    __atomic_load(&(ptp->task_pool_size), &task_pool_size, __ATOMIC_ACQUIRE);
    return task_pool_size;
}

int pthread_pool_reduce_task_pool(struct pthread_pool *ptp, size_t req)
{
    int iret = 0;
    struct ptp_task *ptask;
    if (req < ptp->num_of_threads)
        req = ptp->num_of_threads;
    if (0 == pthread_mutex_lock_with_err(ptp, &(ptp->mtx_pool))) {
        while (req < ptp->task_pool.size) {
            ptask = ptp_task_queue_popfront(&(ptp->task_pool));
            if (NULL != ptask)
                free(ptask);
            else {
                iret = -1;
                break;
            }
        }
        __atomic_store(&(ptp->task_pool_size), &req, __ATOMIC_RELEASE);
        pthread_mutex_unlock(&(ptp->mtx_pool));
    } else
        iret = -1;
    return iret;
}

int pthread_pool_qerror_empty(struct pthread_pool *ptp)
{
    int iret;
    if (0 == pthread_mutex_lock(&(ptp->mtx_error))) {
        iret = ptp_error_queue_empty(&(ptp->error_queue));
        pthread_mutex_unlock(&(ptp->mtx_error));
    } else
        iret = 0;
    return iret;
}

int pthread_pool_qerror_pool(struct ptp_error *perr, struct pthread_pool *ptp)
{
    int iret;
    struct ptp_error *p;
    if (0 == pthread_mutex_lock(&(ptp->mtx_error))) {
        p = ptp_error_queue_popfront(&(ptp->error_queue));
        if (NULL != p) {
            perr->pnext = NULL;
            perr->error = p->error;
            perr->thread_id = p->thread_id;
            ptp_error_queue_pushback(&(ptp->error_pool), p);
            iret = 0;
        } else
            iret = -1;
        pthread_mutex_unlock(&(ptp->mtx_error));
    } else
        iret = -1;
    return iret;
}

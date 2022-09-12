#ifndef __PTHREAD_POOL_H__
#define __PTHREAD_POOL_H__

#define _POSIX_C_SOURCE 200112L

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <semaphore.h>

struct ptp_task {
    struct ptp_task *pnext;
    void (*task_fun_ptr)(void *);
    size_t args[32], args_size;
    size_t task_pool_recursive_idx;
};
struct ptp_task_queue {
    struct ptp_task *phead, *ptail;
    size_t size;
};
int ptp_task_push_arg(struct ptp_task *, const void *, size_t);
void ptp_task_pull_arg(void *, size_t, void **);
void ptp_task_clear(struct ptp_task *);

struct ptp_error {
    struct ptp_error *pnext;
    pthread_t thread_id;
    int error;
};
struct ptp_error_queue {
    struct ptp_error *phead, *ptail;
    size_t size;
};

struct pthread_pool {
    struct ptp_task_queue task_pool;
    struct ptp_task_queue task_queue;
    struct ptp_task_queue task_pool_recursive;
    struct ptp_task_queue task_queue_recursive;
    struct ptp_error_queue error_pool, error_queue;
    size_t num_of_threads, task_pool_size, join_barrier;
    pthread_t *ptr_threads;
    sem_t *ptr_sems_recursive;  /*semaphores for recursive tasks */
    pthread_mutex_t mtx_pool;   /*mutex for guard task_pool */
    pthread_mutex_t mtx_queue;  /*mutex for guard task_queue */
    pthread_mutex_t mtx_pool_recursive; /*mutex for guard task_pool_recursive */
    pthread_mutex_t mtx_queue_recursive;        /*mutex for guard task_queue_recursive */
    pthread_mutex_t mtx_error;  /*mutex for guard error_pool and error_queue */
    pthread_cond_t cnd_hottask_occurred;        /*cond-var for occure hot task */
    pthread_cond_t cnd_freetask_occurred;       /*cond-var for occure free task */
    pthread_cond_t cnd_jointasks_occurred;      /*cond-var for occure joining all tasks in queue */
    pthread_barrier_t brr_jointasks_occurred;   /*barrier for joining tasks */
    uint32_t state;             /*must be modifying by builtins */
    uint32_t flags;
};

#define MAX_REC_CALLS 10
#define MAX_ERROR_POOL 256

int pthread_pool_alloc(struct pthread_pool *, size_t);
int pthread_pool_free(struct pthread_pool *);
struct ptp_task *pthread_pool_balloc_task(struct pthread_pool *);
struct ptp_task *pthread_pool_nballoc_task(struct pthread_pool *, int);
int pthread_pool_add_task(struct pthread_pool *, struct ptp_task *);
int pthread_pool_removeall_tasks(struct pthread_pool *);
int pthread_pool_joinall_tasks(struct pthread_pool *);
size_t pthread_pool_task_pool_size(struct pthread_pool *);
int pthread_pool_reduce_task_pool(struct pthread_pool *, size_t);
int pthread_pool_qerror_empty(struct pthread_pool *);
int pthread_pool_qerror_pool(struct ptp_error *, struct pthread_pool *);

#endif /*__PTHREAD_POOL_H__*/

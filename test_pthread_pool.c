#include "pthread_pool.h"

/*static int get_nthreads(void) {
    int iret;
    DIR *proc_dir;
    const struct dirent *entry;

    proc_dir = opendir("/proc/self/task");
    if (NULL != proc_dir) {
        iret = 0;
        do {
            entry = readdir(proc_dir);
            if(NULL == entry)
                break;
            if(entry->d_name[0] != '.')
                ++iret;
        } while(1);

        if (0 != closedir(proc_dir))
            iret = -1;
    } else
        iret = -1;
    return iret;
}*/

static void print_elapsed(clock_t start_time)
{
    long int whole_seconds, fract_seconds;
    const clock_t elapsed = clock() - start_time;
    whole_seconds = elapsed / CLOCKS_PER_SEC;
    fract_seconds = elapsed - whole_seconds * CLOCKS_PER_SEC;
    if (0 != whole_seconds)
        printf("%ld s ", whole_seconds);
    printf("%#1.3f ms\n", ((const double)fract_seconds) / 1000.0);
}

static struct ptp_task *ptp_nballoc_task(struct pthread_pool *ptp)
{
    return pthread_pool_nballoc_task(ptp, 1);
}

static void task_increment_int_3(void *parg)
{
    /*parg -> { pthread_pool*, size_t* } */
    struct pthread_pool *pthreadpool;
    size_t *p;
    int iballoc;
    uint8_t add1;
    uint16_t add2;
    uint32_t add3;

    ptp_task_pull_arg(&pthreadpool, sizeof(pthreadpool), &parg);
    ptp_task_pull_arg(&p, sizeof(p), &parg);
    ptp_task_pull_arg(&iballoc, sizeof(iballoc), &parg);

    ptp_task_pull_arg(&add1, sizeof(add1), &parg);
    ptp_task_pull_arg(&add2, sizeof(add2), &parg);
    ptp_task_pull_arg(&add3, sizeof(add3), &parg);

    /*++*p; */
    __atomic_add_fetch(p, add1, __ATOMIC_RELAXED);
    __atomic_add_fetch(p, add2, __ATOMIC_RELAXED);
    __atomic_add_fetch(p, add3, __ATOMIC_RELAXED);
}

static void task_increment_int_2(void *parg)
{
    /*parg -> { pthread_pool*, size_t* } */
    struct pthread_pool *pthreadpool;
    struct ptp_task *ptp_task;
    size_t *p;
    int iret, iballoc;
    uint8_t add1;
    uint16_t add2;
    uint32_t add3;

    ptp_task_pull_arg(&pthreadpool, sizeof(pthreadpool), &parg);
    ptp_task_pull_arg(&p, sizeof(p), &parg);
    ptp_task_pull_arg(&iballoc, sizeof(iballoc), &parg);

    ptp_task_pull_arg(&add1, sizeof(add1), &parg);
    ptp_task_pull_arg(&add2, sizeof(add2), &parg);
    ptp_task_pull_arg(&add3, sizeof(add3), &parg);

    ptp_task = iballoc ? pthread_pool_balloc_task(pthreadpool) : ptp_nballoc_task(pthreadpool);
    if (NULL != ptp_task) {
        ptp_task->task_fun_ptr = task_increment_int_3;
        ptp_task->args_size = 0;
        ptp_task_push_arg(ptp_task, &pthreadpool, sizeof(pthreadpool));
        ptp_task_push_arg(ptp_task, &p, sizeof(p));
        ptp_task_push_arg(ptp_task, &(iballoc), sizeof(iballoc));

        ptp_task_push_arg(ptp_task, &add1, sizeof(add1));
        ptp_task_push_arg(ptp_task, &add2, sizeof(add2));
        ptp_task_push_arg(ptp_task, &add3, sizeof(add3));
        iret = pthread_pool_add_task(pthreadpool, ptp_task);
        if (-1 == iret)
            printf("add_task failed\n");
    } else
        printf("(n)balloc returns NULL\n");
}

static void task_increment_int_1(void *parg)
{
    /*parg -> { pthread_pool*, size_t* } */
    struct pthread_pool *pthreadpool;
    struct ptp_task *ptp_task;
    size_t *p;
    int iret, iballoc;
    uint8_t add1;
    uint16_t add2;
    uint32_t add3;

    ptp_task_pull_arg(&pthreadpool, sizeof(pthreadpool), &parg);
    ptp_task_pull_arg(&p, sizeof(p), &parg);
    ptp_task_pull_arg(&iballoc, sizeof(iballoc), &parg);

    ptp_task_pull_arg(&add1, sizeof(add1), &parg);
    ptp_task_pull_arg(&add2, sizeof(add2), &parg);
    ptp_task_pull_arg(&add3, sizeof(add3), &parg);

    ptp_task = iballoc ? pthread_pool_balloc_task(pthreadpool) : ptp_nballoc_task(pthreadpool);
    if (NULL != ptp_task) {
        ptp_task->task_fun_ptr = task_increment_int_2;
        ptp_task->args_size = 0;
        ptp_task_push_arg(ptp_task, &pthreadpool, sizeof(pthreadpool));
        ptp_task_push_arg(ptp_task, &p, sizeof(p));
        ptp_task_push_arg(ptp_task, &(iballoc), sizeof(iballoc));

        ptp_task_push_arg(ptp_task, &add1, sizeof(add1));
        ptp_task_push_arg(ptp_task, &add2, sizeof(add2));
        ptp_task_push_arg(ptp_task, &add3, sizeof(add3));
        iret = pthread_pool_add_task(pthreadpool, ptp_task);
        if (-1 == iret)
            printf("add_task failed\n");
    } else
        printf("(n)balloc returns NULL\n");
}

struct pthread_pool_subtest_struct {
    size_t sz_value, sz_limit;
    struct pthread_pool threadpool;
    int irecursive, iballoc;
    uint8_t add1;
    uint16_t add2;
    uint32_t add3;
};

static void pthread_pool_subtest_route(void *parg)
{
    struct pthread_pool_subtest_struct *const pargs = parg;
    struct pthread_pool *const ptp = &(pargs->threadpool);
    struct ptp_task *ptp_task;
    const char *pstrarg;
    size_t i;
    int iret;

    void (*thrd_routine)(void *) = pargs->irecursive ? task_increment_int_1 : task_increment_int_3;

    for (i = 0; i < pargs->sz_limit; ++i) {
        ptp_task = pargs->iballoc ? pthread_pool_balloc_task(ptp) : ptp_nballoc_task(ptp);
        if (NULL != ptp_task) {
            ptp_task->task_fun_ptr = thrd_routine;
            pstrarg = (const char *)ptp;
            ptp_task_push_arg(ptp_task, &pstrarg, sizeof(pstrarg));
            pstrarg = (const char *)&(pargs->sz_value);
            ptp_task_push_arg(ptp_task, &pstrarg, sizeof(pstrarg));
            ptp_task_push_arg(ptp_task, &(pargs->iballoc), sizeof(pargs->iballoc));

            ptp_task_push_arg(ptp_task, &(pargs->add1), sizeof(pargs->add1));
            ptp_task_push_arg(ptp_task, &(pargs->add2), sizeof(pargs->add2));
            ptp_task_push_arg(ptp_task, &(pargs->add3), sizeof(pargs->add3));
            iret = pthread_pool_add_task(ptp, ptp_task);
            if (-1 == iret)
                printf("add_task failed\n");
            pthread_pool_joinall_tasks(ptp);
        } else
            printf("(n)balloc returns NULL\n");
    }

    pthread_pool_joinall_tasks(ptp);
    printf("middle of thread_pool_test without join %lu\n", pargs->sz_value);

    for (i = 0; i < pargs->sz_limit; ++i) {
        ptp_task = pthread_pool_balloc_task(ptp);
        if (NULL != ptp_task) {
            ptp_task->task_fun_ptr = thrd_routine;
            pstrarg = (const char *)ptp;
            ptp_task_push_arg(ptp_task, &pstrarg, sizeof(pstrarg));
            pstrarg = (const char *)&(pargs->sz_value);
            ptp_task_push_arg(ptp_task, &pstrarg, sizeof(pstrarg));
            ptp_task_push_arg(ptp_task, &(pargs->iballoc), sizeof(pargs->iballoc));

            ptp_task_push_arg(ptp_task, &(pargs->add1), sizeof(pargs->add1));
            ptp_task_push_arg(ptp_task, &(pargs->add2), sizeof(pargs->add2));
            ptp_task_push_arg(ptp_task, &(pargs->add3), sizeof(pargs->add3));
            iret = pthread_pool_add_task(ptp, ptp_task);
            if (-1 == iret)
                printf("add_task failed\n");
        } else
            printf("(n)balloc returns NULL\n");
    }
}

static int pthread_pool_subtest(int recursive, int balloc)
{
    int iret;
    size_t i;
    const clock_t start_time = clock();
    const char *const str1 = recursive ? "recursive" : "non-recursive";
    const char *const str2 = balloc ? "balloc" : "nballoc";
    const size_t num_of_threads = 4;
    struct pthread_pool_subtest_struct test_args;
    pthread_t *pthreads;

    test_args.sz_value = 0;
    test_args.sz_limit = 15000;
    test_args.irecursive = recursive;
    test_args.iballoc = balloc;
    test_args.add1 = 1;
    test_args.add2 = 1;
    test_args.add3 = 1;

    iret = pthread_pool_alloc(&(test_args.threadpool), 1000);
    if (0 == iret) {
        pthreads = malloc(num_of_threads * sizeof(*pthreads));
        for (i = 0; i < num_of_threads; ++i)
            pthread_create(pthreads + i, NULL, pthread_pool_subtest_route, &test_args);
        for (i = 0; i < num_of_threads; ++i)
            pthread_join(pthreads[i], NULL);

        iret = pthread_pool_free(&(test_args.threadpool));
        if (0 != iret)
            printf("failed pthread_pool_free\n");

        /*printf("end of thread_pool_test with join %lu\n", test_args.sz_value); */

        if (test_args.sz_value ==
            num_of_threads * 2 * test_args.sz_limit * (test_args.add1 + test_args.add2 +
                                                       test_args.add3))
            iret = 0;
        else
            iret = -1;

        free(pthreads);
    } else
        printf("failed pthread_pool_alloc\n");

    if (0 == iret) {
        printf("%s %s thread_pool_test ok\n", str1, str2);
        print_elapsed(start_time);
    } else
        printf("%s %s thread_pool_test failed\n", str1, str2);
    printf("\n");

    return iret;
}

int main(void)
{
    int iret;
    iret = pthread_pool_subtest(1, 1);
    iret |= pthread_pool_subtest(0, 1);
    iret |= pthread_pool_subtest(1, 0);
    iret |= pthread_pool_subtest(0, 0);
    printf("END PTHREAD_POOL TEST: %s\n", 0 == iret ? "OK" : "FAIL");
    return iret;
}

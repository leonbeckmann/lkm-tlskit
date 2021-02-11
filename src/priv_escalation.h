#ifndef LKM_TLSKIT_PRIV_ESCALATION_H
#define LKM_TLSKIT_PRIV_ESCALATION_H

/**
 * Make the current task root
 * @return 0 on success, -1 on failure
 */
int privilege_escalation(void);

#endif //LKM_TLSKIT_PRIV_ESCALATION_H

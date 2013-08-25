/*
 *
 * CODENVY CONFIDENTIAL
 * ________________
 *
 * [2012] - [2013] Codenvy, S.A.
 * All Rights Reserved.
 * NOTICE: All information contained herein is, and remains
 * the property of Codenvy S.A. and its suppliers,
 * if any. The intellectual and technical concepts contained
 * herein are proprietary to Codenvy S.A.
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Codenvy S.A..
 */

IMPORT 'macros.pig';

t = loadResources('$LOG', '$FROM_DATE', '$TO_DATE', '$USER', '$WS');

j1 = joinEventsWithSameId(t, 'session-started', 'session-finished');
j2 = FOREACH j1 GENERATE ws, REGEX_EXTRACT(user, '.*@(.*)', 1) AS domain, dt, delta;
j = removeEmptyField(j2, 'domain');

r1 = GROUP j BY domain;
result = FOREACH r1 {
    r2 = FOREACH j GENERATE TOTUPLE(TOTUPLE(ws), TOTUPLE(domain), TOTUPLE(dt), TOTUPLE(delta));
    GENERATE group, r2;
}

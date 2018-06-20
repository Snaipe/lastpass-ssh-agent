/* lastpass-ssh-agent
 * 
 * Copyright (C) 2018  Franklin "Snaipe" Mathieu <me@snai.pe>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef SSH_H_
#define SSH_H_

#include <stdint.h>

/* The following codes are taken from the IETF document
   draft-miller-ssh-agent-00 § 5.2. */

/* SSH agent request codes */
enum {
    SSH_AGENTC_REQUEST_IDENTITIES            = 11,
    SSH_AGENTC_SIGN_REQUEST                  = 13,
    SSH_AGENTC_ADD_IDENTITY                  = 17,
    SSH_AGENTC_REMOVE_IDENTITY               = 18,
    SSH_AGENTC_REMOVE_ALL_IDENTITIES         = 19,
    SSH_AGENTC_ADD_ID_CONSTRAINED            = 25,
    SSH_AGENTC_ADD_SMARTCARD_KEY             = 20,
    SSH_AGENTC_REMOVE_SMARTCARD_KEY          = 21,
    SSH_AGENTC_LOCK                          = 22,
    SSH_AGENTC_UNLOCK                        = 23,
    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26,
    SSH_AGENTC_EXTENSION                     = 27,
};

/* SSH agent response codes */
enum {
    SSH_AGENT_FAILURE           = 5,
    SSH_AGENT_SUCCESS           = 6,
    SSH_AGENT_EXTENSION_FAILURE = 28,
    SSH_AGENT_IDENTITIES_ANSWER = 12,
    SSH_AGENT_SIGN_RESPONSE     = 14,
};

/* SSH signature flags */
enum {
    SSH_AGENT_RSA_SHA2_256 = 2,
    SSH_AGENT_RSA_SHA2_512 = 4,
};

/* defined implicitly by § 7.1 */
#define SSH_CODE_NUM (SSH_AGENT_EXTENSION_FAILURE+1)

#endif /* !SSH_H_ */

# introduction


# Authentication of Machines
## Symmetric Cryptosystems and Authentication
- Review of Shared Key Cryptography / symmetric key crypto
    - {m}k denotes E(k, m)
    - A -> B: m denotes 'A sends m to B'
    - A -> B: r, s, t denotes sending a msg comprising fields r, s, t
    - Dolev-Yao thread model
        - An attacker can intercept messages transmitted between hosts.
        - An attacker can parse any message comprising separately encrypted fields, and the attacker can extract the separate fields. 
        - An attacker can decrypt a message or field if and only if that attacker has previously obtained the appropriate encryption key. 
            - first 3 elements characterize passive attacks
        - An attacker can construct and send new messages using information intercepted from old messages.
            - active attacks
- Uses of Shared Key Cryptography
    - if A and B share key k
        - A -> B: {m}k
    - confidential information might temporarily reside unencrypted on the disk
- Authentication using Shared Key Cryptography
    - authentication protocol 
        - allows a principal receiving a message to determine which principal sent that message
    - weak authentication   
        -  a principal must reveal the secret in order to prove knowledge of that secret
        - subject to replay attacks
    - strong authentication
        - knowledge of the secret is demonstrated without revealing the secret itself
        - e.g. diff challenge every time
    - protocol allows B to authenticate A
        - assume A and B share a secret key
        - 
            ```
            1. B: select and store a new random value r (nounce).
            2.B-->A: B,r #inclusion of 'B' allows receiver A to select the correct shared key 
            3.A-->B: {r}k
            4. B: check whether D(k, {r}k) equals the stored value r from step 1.
            ```
    - reflection attacks
        - A and B are each unwittingly running an "encryption service"
        - an intruder sends information from an on-going protocol execution back to the originator of that information.
        - intruder runs one or more concurrent instances of the protocol and interleaves them with the original.
        - 
            ```
            1. B:  select and store a new random value r.
            2. B --> T:  B,r
                i.  T --> B:  A,r
                ii.  B --> T:  {r}k
            3. T --> B: {r}k
            4. B:  check whether D(k, {r}k) equals the stored value r from step 1.
            ```
        - could be prevented by breaking protocol symmetry
            - e.g. have k_AB and k_BA, where k_AB is used by B when A is the initiator
        - Insist that each response includes the identity of the responder
            - ``3. A --> B:  {A,r}k``
    - man-in-the-middle attacks
        -  T could run two instances of the protocol: 
            - one with A and the other with B
            - engaging as needed whichever of these principals would produce the value being needed by T to perpetuate its deception.
        - 
            ```
            Each protocol step i of the form
                i. X --> Y: m
            is replaced by two steps
                i. X --> T: m
                i' T --> Y: m
            ```
        -  T is indistinguishable from a wire or a network channel
            - which itself might involve multiple store-and-forward routers
    - two compelling reasons for principals to share keys
        - shared keys can be used to implement string authentication
        - shared keys help in defending against man-in-the-middle attacks.
- Key Distribution Protocols
    - need mediated key exchange protocol, else O(N^2) number of keys
    - Each host shares a key with some trusted host KDC (for Key Distribution Center)
    - KDC generates keys, on demand, for pairs of hosts that must communicate.
    - protocol
        - Assume each principal P shares key K_P with KDC.
        - 
            ```
            1. A --> KDC: A,B
            2. KDC --> A: A,B, {K_AB}K_A 
            3. KDC --> B: A,B, {K_AB}K_B
            ```
        - problem
            - A does not know whether B has received the key
        - fix
            ```
            1. A --> KDC: A,B
            2. KDC --> A: A,B, {K_AB}K_A, {K_AB}K_B 
            3. A --> B: A,B, {K_AB}K_B
            ```
        - man-in-the-middle attacks
            ```
            1. A-->T: A,B
            1' T --> KDC: A,T
            2. KDC --> T: A,T, {K_AT}K_A, {K_AT}K_T
                T --> KDC: T,B
                KDC --> T: T,B {K_TB}K_T, {K_TB}K_B 
            2' T --> A: A,B, {K_AT}K_A, {K_TB}K_B
            3. A --> B: A,B, {K_TB}K_B
            ```
        - fix
            ```
            1. A --> KDC: A,B
            2. KDC --> A: {A,B, K_AB, {K_AB}K_B}K_A 
            3. A --> B: A,B, {K_AB}K_B
            ```
        - replay attack
            - message 2 can be replayed by an attacker having intercepted message 1
            - forcing A & B to use an older value of K_AB
            - attacker with an old value of K_AB has incentive to make this happen
        - include nounce r to defend
            ```
            1. A --> KDC: A,B,r where r is a new random value 
            2. KDC --> A: {A,B,r, K_AB, {A,B,K_AB}K_B}K_A
            3. A --> B: A,B, {A,B,K_AB}K_B
            ```
        - Needham-Schroeder Protocol:
            - defend against B being fooled into using an old value of K_AB 
            - adding a challenge-response round to the end of the protocol
                ```
                1. A --> KDC: A,B,r where r is a new random value 
                2. KDC --> A: {A,B,r, K_AB, {A,B,K_AB}K_B}K_A
                3. A --> B: A,B, {A,B,K_AB}K_B
                4. B --> A: {r'}K_AB where r' is a new random value 5. A-->B:{r'+1}K_AB
                ```
            - two cases
                - Suppose the attacker replays an (old) message 3---a message containing an old value of K_AB known to the attacker. But in this case, the attacker would be able to respond to challenge 4, so B is fooled despite adding the challenge-response protocol (messages 4 and 5). (In Kerberos this problem is minimized by including a timestamp in the final field of message 2. B rejects a message 3 that contains a sufficiently old timestamp.)
                - What if the attacker does not know the old value of K_AB that is contained in the old message 3 being replayed? Here, the challenge will not succeed, but the attacker has caused delay and network traffic. On a positive note, B does learn that a shared key has not been established.
- Reality Intrudes: Keys do get compromised
    - The Otway-Rees authentication protocol avoids the above vulnerability
        ```
        1. A --> B: n,A,B, {r1,n,A,B}K_A
        2. B --> KDC: n,A,B, {r1,n,A,B}K_A, {r2,n,A,B}K_B 
        # checking that the same value for n appears in the two requests.
        3. KDC --> B: n,{r1,K_AB}K_A, {r2,K_AB}K_B,
        4. B --> A: n,{r1,K_AB}K_A
        ```
    - there is a nested structure (A; B; KDC; B; A) with Otway-Rees whereas with Needham-Schroeder, A is more of a hub, communicating separately with KDC and with B.
    - KDC can check message 2 to ensure that nonces r1 and r2 are being associated with the same protocol run nonce n, and (because KDC is trusted) send message 3 only if that equality holds.
- type attacks
    - len(n, A, B) = len(K_AB)
    ```
    i. T intercepts Otway-Rees message 1, and extracts substrings "n,A,B" and "{r1,n,A,B}K_A".
    ii. T blocks Otway-Rees protocol message 2 (which means message 3 won't be sent either).
    iii. T then sends back to A as Otway-Rees protocol message 4 the following (which is constructed from information learned by T in step i of this attack): 4. T --> A: n,{r1,n,A,B}K_A
    iv. A will decrypt {r1,n,A,B}K_A believing this bitstring to be {r1,K_AB}K_A. According to the correspondence we assumed above, A will conclude that K_AB equals "n,A,B".
    v. But T knows "n,A,B" from step i of the attack, so T has forced A to accept as a key K_AB shared with B what in fact is a key shared with T
    ```
    - prevented if mix-and-match substitution of different kinds of values is impossible
        - Use of a programming notation in which messages contain typing information is one way to avoid the problem.
- Back to Needham-Schroeder...
    - investigate the consequences of having the key K_A that a principal A shares with KDC compromised.
    ```
    i. Suppose T has intercepted message 2 from an earlier run of Needham-Schroeder where intercepted key K_A was in use. This means that T can extract the value of shared key K_AB being proposed in that message and also can extract "{A,B,K_AB}K_B".
    ii. T now waits for A to start a new execution of Needham-Schroeder to establish a shared key with B. T replaces message 3 in that execution with a message it constructs using "{A,B,K_AB}K_B" that T extracted in step i and that includes old key K_AB.
    iii. Because T knows this old value of K_AB (from step i), T can respond correctly to the challenge that B then sends in Needham-Schroeder message 4. So B will be convinced that this old value of K_AB is the new key it shares with A.

    ```
    - fix: have B create a nounce r''
        ```
        a. A-->B:A,B
        b. B --> A: A,B,r"
        1. A --> KDC: A,B,r,r"
        2. KDC --> A: {A,B,r, K_AB, {A,B,K_AB,r"}K_B}K_A
        3. A --> B: A,B, {A,B,K_AB,r"}K_B
        4. B --> A: {r'}K_AB where r' is a new random value 5. A-->B:{r'+1}K_AB
        ```
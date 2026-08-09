-- Level 1: SQL Injection
-- Real password: 'not_needed_for_sqli'
INSERT INTO auth_users VALUES (1, 'admin_sqli', 'not_needed_for_sqli', NULL, 'PLAIN', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
-- Real password: 'v9K#2mLp!8zQ'
INSERT INTO auth_users VALUES (2, 'admin_logs', 'v9K#2mLp!8zQ', NULL, 'PLAIN', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: password stored as a BCrypt (cost 12) hash rather than plaintext
-- Real password: 'b7X$4nRj-6mW'
INSERT INTO auth_users VALUES (3, 'admin_plain', '$2a$12$.hggXFP5QDRzs07jw.XGOeM5gB06vSHTlc.2MopApbTrpB4/4Nyvu', NULL, 'BCRYPT', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: MD5 Hashing (f2C@9tYk*1hP)
INSERT INTO auth_users VALUES (4, 'admin_md5', '0168b6037606df265be7f1f5d9c0e7fe', NULL, 'MD5', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: SHA1 Hashing (x5B&3gHq+7vS)
INSERT INTO auth_users VALUES (5, 'admin_sha1', '632e10860bd26278451d3f89d1c46f180e5623e0', NULL, 'SHA1', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: SHA-256 (No Salt) (m8D!4kLr#2jZ)
INSERT INTO auth_users VALUES (6, 'admin_sha256', '8b8eca84f7e2b04f531749f999c3bf9e3f045bab78f4c8a451fa70929b3c3946', NULL, 'SHA256', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: Salted SHA-256 (q1W%6nTp^8vM with Salt s9A#2zLk)
INSERT INTO auth_users VALUES (7, 'admin_enum', '71ad23cc508b5658f0bc21d8323f55521be98ca951e83a4a4d15641a3ca2b8a4', 's9A#2zLk', 'SHA256', 7, 'admin_enum@example.com', 'ADMIN');

-- Level 8: Bcrypt (cost 12) over a high-entropy password instead of 'password123',
-- which sits near the top of every credential-stuffing wordlist
-- Bcrypt hash for 'T4v#9pQz!7mK^2wE'
INSERT INTO auth_users VALUES (8, 'admin_weak', '$2a$12$65xIdRFf5Y7tCZtZWVzSwe.fvKz.lQE1.8i1hPJ5PfR2Ee48j04Na', NULL, 'BCRYPT', 8, 'admin_weak@example.com', 'ADMIN');

-- Level 9: Secure (Bcrypt + Generic Error) (9fG#2hJk*LmN!8qR)
-- Bcrypt hash for '9fG#2hJk*LmN!8qR'
INSERT INTO auth_users VALUES (9, 'admin_secure', '$2a$10$1WiFUNqUY/vHTzR2QtuMQuzCLK3aZEdjEUpqS4msXOevaCz7Wobe.', NULL, 'BCRYPT', 9, 'admin_secure@example.com', 'ADMIN');

-- Level 10: BCrypt at cost 12 rather than cost 4, over a high-entropy password.
-- A cost-4 hash is roughly 256x cheaper to attack, which puts an offline crack of a
-- common password like 'sunshine' within trivial reach.
-- Bcrypt hash (cost 12) for 'R8k$3mVx!5nJ&1qT'
INSERT INTO auth_users VALUES (10, 'admin_lowcost', '$2a$12$a5hCz.qigE7W1u.SLFolUuW2cCR2dJxHGGCeqnzP7ORFe/CQkBx5a', NULL, 'BCRYPT', 10, 'admin_lowcost@example.com', 'ADMIN');

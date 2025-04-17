INSERT INTO users (username, password, email, full_name, last_password_change, account_locked, login_attempts, last_login, created_at, updated_at)
VALUES
    ('testuser1', '$2a$12$nNcNJtl3p7/h2FH8HKRW1Ofc3uHN7P./mBuKyaNRA3QUMUPRsS5Pu', 'test1@example.com', 'Test User 1', CURRENT_TIMESTAMP(), FALSE, 0, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser2', '$2a$12$nNcNJtl3p7/h2FH8HKRW1Ofc3uHN7P./mBuKyaNRA3QUMUPRsS5Pu', 'test2@example.com', 'Test User 2', DATEADD('DAY', -100, CURRENT_TIMESTAMP()), FALSE, 0, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser3', '$2a$12$nNcNJtl3p7/h2FH8HKRW1Ofc3uHN7P./mBuKyaNRA3QUMUPRsS5Pu', 'test3@example.com', 'Test User 3', DATEADD('DAY', -99, CURRENT_TIMESTAMP()), FALSE, 0, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser4', '$2a$12$nNcNJtl3p7/h2FH8HKRW1Ofc3uHN7P./mBuKyaNRA3QUMUPRsS5Pu', 'test4@example.com', 'Test User 4', DATEADD('DAY', -98, CURRENT_TIMESTAMP()), FALSE, 0, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser5', '$2a$12$nNcNJtl3p7/h2FH8HKRW1Ofc3uHN7P./mBuKyaNRA3QUMUPRsS5Pu', 'test5@example.com', 'Test User 5', DATEADD('DAY', -97, CURRENT_TIMESTAMP()), FALSE, 0, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser6', '$2a$12$nNcNJtl3p7/h2FH8HKRW1Ofc3uHN7P./mBuKyaNRA3QUMUPRsS5Pu', 'test6@example.com', 'Test User 6', DATEADD('DAY', -96, CURRENT_TIMESTAMP()), FALSE, 0, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser7', '$2a$12$nNcNJtl3p7/h2FH8HKRW1Ofc3uHN7P./mBuKyaNRA3QUMUPRsS5Pu', 'test7@example.com', 'Test User 7', DATEADD('DAY', -95, CURRENT_TIMESTAMP()), FALSE, 0, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP());

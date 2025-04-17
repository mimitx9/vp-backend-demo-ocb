-- Initial demo data for users table
INSERT INTO users (username, email, first_name, last_name, ciam_id, last_login, created_at, updated_at)
VALUES
    ('testuser1', 'test1@example.com', 'Test 1', 'User 1', 'ciam_123456', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser2', 'test2@example.com', 'Test 2', 'User 2', 'ciam_123457', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser3', 'test3@example.com', 'Test 3', 'User 3', 'ciam_123458', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser4', 'test4@example.com', 'Test 4', 'User 4', 'ciam_123459', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser5', 'test5@example.com', 'Test 5', 'User 5', 'ciam_1234510', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser6', 'test6@example.com', 'Test 6', 'User 6', 'ciam_1234511', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser7', 'test7@example.com', 'Test 7', 'User 7', 'ciam_1234512', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP());

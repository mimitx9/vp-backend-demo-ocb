-- Initial demo data for users table
INSERT INTO users (username, email, first_name, last_name, address, last_login, created_at, updated_at)
VALUES
    ('testuser1', 'test1@example.com', 'Test 1', 'User 1', '89 Lang Ha', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser2', 'test2@example.com', 'Test 2', 'User 2', '89 Hoang Cau', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser3', 'test3@example.com', 'Test 3', 'User 3', '89 Dong Da', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser4', 'test4@example.com', 'Test 4', 'User 4', '89 Hai Ba Trung', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser5', 'test5@example.com', 'Test 5', 'User 5', '89 Minh Khai', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser6', 'test6@example.com', 'Test 6', 'User 6', '89 Ca Mau', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser7', 'test7@example.com', 'Test 7', 'User 7', '89 Dong ANh', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP());

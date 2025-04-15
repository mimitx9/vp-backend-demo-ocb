-- Initial demo data for users table
-- Passwords are BCrypt hashed - the plain text password is 'Password123!'
INSERT INTO users (username, password, email, full_name, last_password_change, account_locked, login_attempts, last_login, created_at, updated_at)
VALUES
    ('testuser1', '$2a$10$AArX9RHZUc9zq9El1JhMEO7XoOgNGVXBC1.1XhAZXBvdl7pPe9XHu', 'test1@example.com', 'Test User One', CURRENT_TIMESTAMP(), FALSE, 0, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('testuser2', '$2a$10$AArX9RHZUc9zq9El1JhMEO7XoOgNGVXBC1.1XhAZXBvdl7pPe9XHu', 'test2@example.com', 'Test User Two', DATEADD('DAY', -100, CURRENT_TIMESTAMP()), FALSE, 0, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('lockeduser', '$2a$10$AArX9RHZUc9zq9El1JhMEO7XoOgNGVXBC1.1XhAZXBvdl7pPe9XHu', 'locked@example.com', 'Locked User', CURRENT_TIMESTAMP(), TRUE, 5, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP());
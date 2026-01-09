-- Admin users (separate from regular users for security)
CREATE TABLE admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    avatar VARCHAR(500),
    is_active BOOLEAN DEFAULT TRUE,
    is_super_admin BOOLEAN DEFAULT FALSE,
    last_login_at TIMESTAMP NULL,
    last_login_ip VARCHAR(45),
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Admin roles
CREATE TABLE admin_roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Admin permissions
CREATE TABLE admin_permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) DEFAULT 'general',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Admin role permissions
CREATE TABLE admin_role_permissions (
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES admin_roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES admin_permissions(id) ON DELETE CASCADE
);

-- Admin user roles
CREATE TABLE admin_user_roles (
    admin_user_id INT NOT NULL,
    role_id INT NOT NULL,
    PRIMARY KEY (admin_user_id, role_id),
    FOREIGN KEY (admin_user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES admin_roles(id) ON DELETE CASCADE
);

-- System audit logs
CREATE TABLE system_audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_user_id INT NULL,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id INT NULL,
    details JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_action (action),
    INDEX idx_resource (resource_type, resource_id),
    INDEX idx_created_at (created_at),
    FOREIGN KEY (admin_user_id) REFERENCES admin_users(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- System settings
CREATE TABLE system_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    key_name VARCHAR(100) NOT NULL,
    value TEXT,
    type VARCHAR(20) DEFAULT 'string',
    description TEXT,
    is_public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_setting (category, key_name),
    INDEX idx_category (category)
);

-- API keys (for admin access)
CREATE TABLE admin_api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_user_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    api_key VARCHAR(64) UNIQUE NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,
    scopes JSON,
    rate_limit INT DEFAULT 100,
    expires_at TIMESTAMP NULL,
    last_used_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    INDEX idx_api_key (api_key)
);

-- Admin sessions
CREATE TABLE admin_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_user_id INT NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    access_token_hash VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    INDEX idx_session_id (session_id),
    INDEX idx_admin_user (admin_user_id)
);

-- Insert default admin roles and permissions
INSERT INTO admin_roles (name, description, is_default) VALUES 
('Super Admin', 'Full system access', FALSE),
('Administrator', 'Manage users and content', TRUE),
('Moderator', 'Moderate content and users', TRUE),
('Viewer', 'View-only access', TRUE);

-- Insert permissions
INSERT INTO admin_permissions (code, name, description, category) VALUES
-- User Management
('users.view', 'View Users', 'View user list and details', 'users'),
('users.create', 'Create Users', 'Create new users', 'users'),
('users.edit', 'Edit Users', 'Edit user information', 'users'),
('users.delete', 'Delete Users', 'Delete users', 'users'),
('users.impersonate', 'Impersonate Users', 'Login as another user', 'users'),
('users.export', 'Export Users', 'Export user data', 'users'),

-- Role Management
('roles.view', 'View Roles', 'View role list and details', 'roles'),
('roles.create', 'Create Roles', 'Create new roles', 'roles'),
('roles.edit', 'Edit Roles', 'Edit role permissions', 'roles'),
('roles.delete', 'Delete Roles', 'Delete roles', 'roles'),
('roles.assign', 'Assign Roles', 'Assign roles to users', 'roles'),

-- API Key Management
('apikeys.view', 'View API Keys', 'View API key list', 'apikeys'),
('apikeys.create', 'Create API Keys', 'Create new API keys', 'apikeys'),
('apikeys.edit', 'Edit API Keys', 'Edit API key settings', 'apikeys'),
('apikeys.delete', 'Delete API Keys', 'Revoke API keys', 'apikeys'),

-- System Management
('system.logs.view', 'View System Logs', 'View audit logs', 'system'),
('system.logs.clear', 'Clear System Logs', 'Clear audit logs', 'system'),
('system.metrics.view', 'View Metrics', 'View system metrics', 'system'),
('system.settings.view', 'View Settings', 'View system settings', 'system'),
('system.settings.edit', 'Edit Settings', 'Edit system settings', 'system'),
('system.backup', 'System Backup', 'Create system backups', 'system'),

-- Dashboard
('dashboard.view', 'View Dashboard', 'Access admin dashboard', 'dashboard'),

-- Admin User Management
('admin_users.view', 'View Admin Users', 'View admin user list', 'admin'),
('admin_users.create', 'Create Admin Users', 'Create new admin users', 'admin'),
('admin_users.edit', 'Edit Admin Users', 'Edit admin users', 'admin'),
('admin_users.delete', 'Delete Admin Users', 'Delete admin users', 'admin');

-- Assign permissions to Super Admin role
INSERT INTO admin_role_permissions (role_id, permission_id)
SELECT 
    (SELECT id FROM admin_roles WHERE name = 'Super Admin'),
    id 
FROM admin_permissions;

-- Assign default permissions to Administrator role
INSERT INTO admin_role_permissions (role_id, permission_id) VALUES
((SELECT id FROM admin_roles WHERE name = 'Administrator'), (SELECT id FROM admin_permissions WHERE code = 'users.view')),
((SELECT id FROM admin_roles WHERE name = 'Administrator'), (SELECT id FROM admin_permissions WHERE code = 'users.create')),
((SELECT id FROM admin_roles WHERE name = 'Administrator'), (SELECT id FROM admin_permissions WHERE code = 'users.edit')),
((SELECT id FROM admin_roles WHERE name = 'Administrator'), (SELECT id FROM admin_permissions WHERE code = 'users.delete')),
((SELECT id FROM admin_roles WHERE name = 'Administrator'), (SELECT id FROM admin_permissions WHERE code = 'roles.view')),
((SELECT id FROM admin_roles WHERE name = 'Administrator'), (SELECT id FROM admin_permissions WHERE code = 'apikeys.view')),
((SELECT id FROM admin_roles WHERE name = 'Administrator'), (SELECT id FROM admin_permissions WHERE code = 'apikeys.create')),
((SELECT id FROM admin_roles WHERE name = 'Administrator'), (SELECT id FROM admin_permissions WHERE code = 'dashboard.view'));

-- Create initial super admin user (password: Admin123!)
INSERT INTO admin_users (username, email, password, name, is_super_admin) VALUES
('superadmin', 'admin@example.com', '$2y$10$YourHashedPasswordHere', 'Super Admin', TRUE);

-- Assign super admin role
INSERT INTO admin_user_roles (admin_user_id, role_id) VALUES
(1, (SELECT id FROM admin_roles WHERE name = 'Super Admin'));
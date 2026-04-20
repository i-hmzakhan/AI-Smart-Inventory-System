-- Create a dedicated "Inventory Manager" user
CREATE USER 'inventory_app'@'localhost' IDENTIFIED BY 'HSk555';

-- Grant specific DML privileges (Data Manipulation Language)
-- We only give it what it needs: SELECT, INSERT, and UPDATE
GRANT SELECT, INSERT, UPDATE ON smart_inventory.inventory_scans TO 'inventory_app'@'localhost';

-- Apply the changes
FLUSH PRIVILEGES;
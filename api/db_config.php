<?php
$host = '127.0.0.1:3307'; // Using the IP instead of 'localhost' is more stable in XAMPP
$db   = 'smart_inventory';
$user = 'inventory_app';
$pass = 'HSk555';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, // FIXED: Removed _MODE_
    PDO::ATTR_EMULATE_PREPARES   => false,           // Use lowercase false
];

try {
     $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
     throw new \PDOException($e->getMessage(), (int)$e->getCode());
}

?>
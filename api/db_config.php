<?php

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_lifetime', 0);
    ini_set('session.gc_maxlifetime', 0);
    session_set_cookie_params(0);
    session_start();
}
$host = '127.0.0.1:3307'; 
$db   = 'malware_db';
$user = 'inventory_app';
$pass = 'HSk555';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
     $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
     throw new \PDOException($e->getMessage(), (int)$e->getCode());
}
?>
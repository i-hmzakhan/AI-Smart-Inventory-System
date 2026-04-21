<?php
session_start();
require_once 'db_config.php';

// 1. HANDLE LOGIN
if (isset($_POST['login'])) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
    $stmt->execute([$_POST['user'], $_POST['pass']]);
    $user = $stmt->fetch();

    if ($user) {
        $_SESSION['user_id'] = $user['user_id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
    } else {
        $error = "Invalid credentials!";
    }
}

// 2. HANDLE LOGOUT
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
}

// 3. SHOW LOGIN FORM IF NOT LOGGED IN
if (!isset($_SESSION['user_id'])): ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Malware Warehouse Login</title>
    <style>
        body { background: #0f0f0f; color: white; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .login-card { background: #1a1a1a; padding: 40px; border-radius: 8px; border: 1px solid #00ffcc; text-align: center; }
        input { display: block; width: 100%; margin: 10px 0; padding: 10px; background: #222; border: 1px solid #444; color: white; }
        button { background: #00ffcc; color: black; border: none; padding: 10px 20px; cursor: pointer; width: 100%; font-weight: bold; }
    </style>
</head>
<body>
    <div class="login-card">
        <h2>🛡️ Forensic Vault Access</h2>
        <form method="POST">
            <input type="text" name="user" placeholder="Username" required>
            <input type="password" name="pass" placeholder="Password" required>
            <button type="submit" name="login">Enter System</button>
        </form>
        <?php if(isset($error)) echo "<p style='color:red'>$error</p>"; ?>
    </div>
</body>
</html>
<?php exit(); endif; ?>

<?php
# Fetch the latest 10 reports with their features for display on the dashboard
$stmt = $pdo->query("SELECT r.*, f.full_feature_json 
                     FROM malware_reports r 
                     LEFT JOIN malware_features f ON r.report_id = f.report_id 
                     ORDER BY r.captured_at DESC LIMIT 10");
$reports = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html>
<head>
    <title>Forensic Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #121212; color: #eee; padding: 40px; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .role-badge { padding: 5px 10px; border-radius: 4px; font-size: 0.8em; background: <?php echo $_SESSION['role'] == 'root' ? '#ff3366' : '#00ffcc'; ?>; color: black; }
        .scan-card { background: #1a1a1a; padding: 20px; margin-top: 20px; border-radius: 8px; border-left: 5px solid #444; }
        .mgmt-link { color: #ffcc00; font-weight: bold; text-decoration: none; border: 1px solid #ffcc00; padding: 10px; border-radius: 4px; }
        .feature-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; background: #0a0a0a; padding: 15px; margin-top: 10px; border-radius: 5px;font-size: 0.85em;display: none; /* Hidden by default */}
        .feature-item { color: #888; border-bottom: 1px solid #222; padding: 2px; }
        .feature-item span { color: #00ffcc; float: right; }
        .toggle-btn { background: none; border: 1px solid #444; color: #888; padding: 5px 10px; cursor: pointer; border-radius: 4px; transition: 0.3s; }
        .toggle-btn:hover { border-color: #00ffcc; color: #fff; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>📦 Forensic Intelligence Dashboard</h1>
            <p>Welcome, <strong><?php echo $_SESSION['username']; ?></strong> <span class="role-badge"><?php echo strtoupper($_SESSION['role']); ?></span></p>
        </div>
        <div>
            <?php if ($_SESSION['role'] === 'root'): ?>
                <a href="manage_reports.php" class="mgmt-link">⚙️ Root CRUD Panel</a>
            <?php endif; ?>
            <a href="?logout=1" style="color: #888; margin-left: 20px;">Logout</a>
        </div>
    </div>

    <div class="main-content">
        <?php foreach ($reports as $r): 
            $features = json_decode($r['full_feature_json'], true);
        ?>
            <div class="scan-card">
                <div style="float: right;">
                    <button class="toggle-btn" onclick="toggleFeatures(<?php echo $r['report_id']; ?>)">🧬 View Heuristic DNA</button>
                </div>
                <span style="color: #888;">SHA-256: <?php echo substr($r['sha256_hash'], 0, 32); ?>...</span>
                <h3>File: <?php echo $r['file_name']; ?></h3>
                <p>Status: <strong style="color: <?php echo $r['threat_level'] == 'CRITICAL' ? '#ff3366' : '#00ffcc'; ?>"><?php echo $r['threat_level']; ?></strong> | Entropy: <?php echo round($r['entropy_score'], 2); ?></p>

                <div id="features-<?php echo $r['report_id']; ?>" class="feature-grid">
                    <?php if ($features && is_array($features)): ?>
                        <?php foreach ($features as $name => $value): ?>
                            <div class="feature-item">
                                <?php echo $name; ?>: <span><?php echo is_numeric($value) ? round($value, 4) : $value; ?></span>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <p>No feature data available for this record.</p>
                    <?php endif; ?>
                </div>
            </div>
            
        <?php endforeach; ?>
        <div class="form-section" style="border: 1px solid #00ffcc; padding: 20px; border-radius: 8px;">
            <h3>☣️ Live Malware Triage Station</h3>
            <form action="process_scan.php" method="POST" enctype="multipart/form-data">
                <label>Select PE Binary (.exe) for AI Analysis:</label><br><br>
                <input type="file" name="malware_sample" required>
                <button type="submit" class="btn-add">Run V3 Engine</button>
            </form>
        </div>

        <script>
        function toggleFeatures(id) {
            var x = document.getElementById("features-" + id);
            if (x.style.display === "grid") {
                x.style.display = "none";
            } else {
                x.style.display = "grid";
            }
        }
        </script>
    </div>
</body>
</html>

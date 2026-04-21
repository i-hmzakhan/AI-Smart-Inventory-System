<?php
require_once 'db_config.php';

// 1. SECURITY CHECK
session_start();
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'root') {
    die("⛔ Access Denied: This area requires Root privileges.");
}

// 2. CREATE (Manual Ingest)
if (isset($_POST['manual_ingest'])) {
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("INSERT INTO malware_reports (file_name, sha256_hash, entropy_score, malware_probability, threat_level) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$_POST['fname'], $_POST['fhash'], $_POST['fent'], $_POST['fprob'], $_POST['flevel']]);
        
        $report_id = $pdo->lastInsertId();
        // Insert dummy features for manual entry consistency
        $stmt2 = $pdo->prepare("INSERT INTO malware_features (report_id, num_strings, full_feature_json) VALUES (?, ?, ?)");
        $stmt2->execute([$report_id, 0, json_encode(['manual' => true])]);
        
        $pdo->commit();
        $msg = "Record Created Successfully!";
    } catch (Exception $e) {
        $pdo->rollBack();
        $msg = "Error: " . $e->getMessage();
    }
}

// 3. DELETE
if (isset($_GET['delete_id'])) {
    $stmt = $pdo->prepare("DELETE FROM malware_reports WHERE report_id = ?");
    $stmt->execute([$_GET['delete_id']]);
    header("Location: manage_reports.php?msg=Deleted");
}

// 4. UPDATE
if (isset($_POST['update_status'])) {
    $stmt = $pdo->prepare("UPDATE malware_reports SET threat_level = ? WHERE report_id = ?");
    $stmt->execute([$_POST['new_level'], $_POST['report_id']]);
}

// 5. READ
$reports = $pdo->query("SELECT * FROM malware_reports ORDER BY captured_at DESC")->fetchAll();
?>

<!DOCTYPE html>
<html>
<head>
    <title>Root Admin - Forensic CRUD</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #0f0f0f; color: #e0e0e0; padding: 30px; }
        .form-section { background: #1a1a1a; padding: 20px; border-radius: 8px; margin-bottom: 30px; border: 1px solid #333; }
        input, select { background: #252525; color: white; border: 1px solid #444; padding: 8px; margin: 5px; border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; background: #1a1a1a; }
        th, td { padding: 12px; border: 1px solid #333; text-align: left; }
        th { background: #252525; color: #00ffcc; }
        .btn-add { background: #00ffcc; color: #000; font-weight: bold; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn-del { color: #ff3366; text-decoration: none; font-weight: bold; }
    </style>
</head>
<body>
    <h1>🔐 Root Malware Management (Full CRUD)</h1>

    <div class="form-section">
        <h3>➕ Manual Threat Ingest (Create)</h3>
        <form method="POST">
            <input type="text" name="fname" placeholder="File Name" required>
            <input type="text" name="fhash" placeholder="SHA-256 Hash" required>
            <input type="number" step="0.01" name="fent" placeholder="Entropy (e.g. 6.5)" required>
            <input type="number" step="0.01" name="fprob" placeholder="Prob (0-1)" required>
            <select name="flevel">
                <option value="CLEAN">CLEAN</option>
                <option value="SUSPICIOUS">SUSPICIOUS</option>
                <option value="CRITICAL">CRITICAL</option>
            </select>
            <button type="submit" name="manual_ingest" class="btn-add">Add to Warehouse</button>
        </form>
        <?php if(isset($msg)) echo "<p style='color:#00ffcc'>$msg</p>"; ?>
    </div>

    <h3>📂 Managed Forensic Records</h3>
    <table>
        <tr>
            <th>ID</th><th>File Identity</th><th>Entropy</th><th>Threat Status (Update)</th><th>Actions</th>
        </tr>
        <?php foreach ($reports as $r): ?>
        <tr>
            <td><?php echo $r['report_id']; ?></td>
            <td>
                <strong><?php echo $r['file_name']; ?></strong><br>
                <small><?php echo substr($r['sha256_hash'], 0, 20); ?>...</small>
            </td>
            <td><?php echo round($r['entropy_score'], 3); ?></td>
            <td>
                <form method="POST">
                    <input type="hidden" name="report_id" value="<?php echo $r['report_id']; ?>">
                    <select name="new_level">
                        <option value="CLEAN" <?php if($r['threat_level']=='CLEAN') echo 'selected'; ?>>CLEAN</option>
                        <option value="SUSPICIOUS" <?php if($r['threat_level']=='SUSPICIOUS') echo 'selected'; ?>>SUSPICIOUS</option>
                        <option value="CRITICAL" <?php if($r['threat_level']=='CRITICAL') echo 'selected'; ?>>CRITICAL</option>
                    </select>
                    <button type="submit" name="update_status">Save</button>
                </form>
            </td>
            <td>
                <a href="?delete_id=<?php echo $r['report_id']; ?>" class="btn-del" onclick="return confirm('Permanently delete this forensic record?')">🗑️ Delete</a>
            </td>
        </tr>
        <?php endforeach; ?>
    </table>
</body>
</html>
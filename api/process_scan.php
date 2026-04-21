<?php
session_start();
require_once 'db_config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['malware_sample'])) {
    $target_dir = "quarantine/";
    
    if (!is_dir($target_dir)) {
        mkdir($target_dir, 0777, true);
    }

    $file_name = basename($_FILES["malware_sample"]["name"]);
    $target_file = $target_dir . $file_name;

    if (move_uploaded_file($_FILES["malware_sample"]["tmp_name"], $target_file)) {
        
        // 1. EXECUTE AI ENGINE
        $python_path = "E:/Sem-03/Database Labs/Project/.venv/Scripts/python.exe"; 
        $script_path = "E:/Sem-03/Database Labs/Project/ai_model/triage.py";
        
        $command = "\"$python_path\" \"$script_path\" \"$target_file\" 2>&1";
        $output = shell_exec($command);
        
        // 2. PARSE JSON
        $lines = explode("\n", trim($output));
        $last_line = end($lines);
        $result = json_decode($last_line, true);
        
        if ($result && isset($result['success']) && $result['success'] === true) {
            $prob = $result['probability'];
            $features = $result['features']; 
            $file_hash = hash_file('sha256', $target_file);
            $feature_json = json_encode($features);

            if ($feature_json === false || $feature_json === "null") {
                die("❌ JSON Encode Error: " . json_last_error_msg());
            }

            // --- 🧠 THE "PAST RECORDS" INTELLIGENCE LOGIC ---
            // Check if we already have this file and if a human manually set the level
            $checkStmt = $pdo->prepare("SELECT threat_level FROM malware_reports WHERE sha256_hash = ?");
            $checkStmt->execute([$file_hash]);
            $existingRecord = $checkStmt->fetch();

            if ($existingRecord) {
                // If the record exists, we keep the OLD level (the database's memory)
                // This ensures if you manually marked it 'CRITICAL', the AI won't reset it to 'CLEAN'
                $level = $existingRecord['threat_level'];
                $status_msg = "Recognized from Database";
            } else {
                // If it's a brand new file, we use the AI Model's logic
                $level = ($prob > 0.7) ? 'CRITICAL' : (($prob > 0.3) ? 'SUSPICIOUS' : 'CLEAN');
                $status_msg = "New Analysis Saved";
            }
            // ------------------------------------------------

            // 3. DATABASE INGESTION
            try {
                $pdo->beginTransaction();

                $entropy = isset($features['entropy']) ? $features['entropy'] : 0;
                
                // INSERT OR UPDATE Main Report
                // We use VALUES(threat_level) so that it respects the $level we defined above
                $stmt = $pdo->prepare("
                    INSERT INTO malware_reports (file_name, sha256_hash, entropy_score, malware_probability, threat_level) 
                    VALUES (?, ?, ?, ?, ?)
                    ON DUPLICATE KEY UPDATE 
                    captured_at = CURRENT_TIMESTAMP,
                    malware_probability = VALUES(malware_probability),
                    threat_level = VALUES(threat_level), 
                    file_name = VALUES(file_name)
                ");
                $stmt->execute([$file_name, $file_hash, $entropy, $prob, $level]);
                
                $report_id = $pdo->lastInsertId();
                if ($report_id == 0) {
                    $stmt_id = $pdo->prepare("SELECT report_id FROM malware_reports WHERE sha256_hash = ?");
                    $stmt_id->execute([$file_hash]);
                    $report_id = $stmt_id->fetchColumn();
                }
                
                // INSERT OR UPDATE Feature DNA
                $num_strings = isset($features['numstrings']) ? $features['numstrings'] : 0;
                $stmt2 = $pdo->prepare("
                    INSERT INTO malware_features (report_id, num_strings, full_feature_json) 
                    VALUES (?, ?, ?)
                    ON DUPLICATE KEY UPDATE 
                    full_feature_json = VALUES(full_feature_json),
                    num_strings = VALUES(num_strings)
                ");
                $stmt2->execute([$report_id, $num_strings, $feature_json]);
                
                $pdo->commit();
                
                if (file_exists($target_file)) {
                    unlink($target_file); 
                }
                
                header("Location: index.php?msg=" . urlencode($status_msg));
                exit();

            } catch (Exception $e) {
                $pdo->rollBack();
                die("Database Error: " . $e->getMessage());
            }
        } else {
            die("AI Engine Error: " . htmlspecialchars($output));
        }
    }
}
?>
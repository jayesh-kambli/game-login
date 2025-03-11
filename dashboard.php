<?php
session_start();
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "user_data";

// Enable error reporting for debugging
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die(json_encode(['success' => false, 'message' => 'Database connection failed.']));
}

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    die(json_encode(['success' => false, 'message' => 'User not logged in.']));
}

$user_id = $_SESSION['user_id'];
$data = json_decode(file_get_contents("php://input"), true);
$client_ip = isset($data['ip']) ? filter_var($data['ip'], FILTER_VALIDATE_IP) : null;

$ipUpdated = false; // Track if IP update was successful

if ($client_ip) {
    // Always update the IP
    $updateIpStmt = $conn->prepare("UPDATE users SET ip = ? WHERE id = ?");
    $updateIpStmt->bind_param("si", $client_ip, $user_id);
    
    if ($updateIpStmt->execute()) {
        $ipUpdated = true; // Mark update as successful
    }
    $updateIpStmt->close();
}

// Fetch user details
$stmt = $conn->prepare("SELECT name, whitelist FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    echo json_encode([
        'success' => true,
        'name' => $row['name'],
        'whitelisted' => $row['whitelist'],
        'ip_updated' => $ipUpdated // Send IP update status
    ]);
} else {
    echo json_encode(['success' => false, 'message' => 'User not found.', 'id' => $user_id]);
}

$stmt->close();
$conn->close();
?>

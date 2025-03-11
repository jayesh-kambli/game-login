<?php
session_start();

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "user_data";

// Create connection
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die(json_encode(['success' => false, 'message' => 'Database connection failed.']));
}

// Get data from the POST request
$data = json_decode(file_get_contents('php://input'), true);

// Validate and sanitize inputs
$name = htmlspecialchars($data['name'], ENT_QUOTES, 'UTF-8');
$ip = filter_var($data['ip'], FILTER_VALIDATE_IP) ?: '127.0.0.1';
// $whitelist = isset($data['whitelist']) && $data['whitelist'] == 1 ? 1 : 0;
$whitelist = 1;

// Check if username already exists
$checkStmt = $conn->prepare("SELECT id FROM users WHERE name = ?");
$checkStmt->bind_param("s", $name);
$checkStmt->execute();
$checkStmt->store_result();

if ($checkStmt->num_rows > 0) {
    die(json_encode(['success' => false, 'message' => 'Username already taken.']));
}
$checkStmt->close();

// Validate password
if (strlen($data['password']) < 8) {
    die(json_encode(['success' => false, 'message' => 'Password must be at least 8 characters long.']));
}
// $password = password_hash($data['password'], PASSWORD_DEFAULT);
$password = hash('sha256', $data['password']);

// Insert data using prepared statements
$stmt = $conn->prepare("INSERT INTO users (name, password, ip, whitelist) VALUES (?, ?, ?, ?)");
$stmt->bind_param("sssi", $name, $password, $ip, $whitelist);

if ($stmt->execute()) {
    echo json_encode(['success' => true, 'message' => 'Registration successful!']);
} else {
    echo json_encode(['success' => false, 'message' => 'Registration failed. Please try again.']);
}

$stmt->close();
$conn->close();
?>

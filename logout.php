<?php
session_start();

// Check if session exists
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'No active session']);
    exit;
}

// Database connection
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "user_data";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die(json_encode(['success' => false, 'message' => 'Database connection failed']));
}

// Get user ID from session
$user_id = $_SESSION['user_id'];

// Reset IP to 0.0.0.0
$stmt = $conn->prepare("UPDATE users SET ip = '0.0.0.0' WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->close();

// Destroy session
session_destroy();
$conn->close();

// Set correct JSON header
header('Content-Type: application/json');
echo json_encode(['success' => true, 'message' => 'Logged out and IP reset']);
?>

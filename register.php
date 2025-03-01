<?php
session_start();

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "user_data";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get data from the POST request
$data = json_decode(file_get_contents('php://input'), true);

// Validate and sanitize inputs
$name = filter_var($data['name'], FILTER_SANITIZE_STRING);
$ip = filter_var($data['ip'], FILTER_VALIDATE_IP);
$whitelist = isset($data['whitelist']) && $data['whitelist'] == 1 ? 1 : 0;

// Validate password
if (strlen($data['password']) < 8) {
    die("Password must be at least 8 characters long.");
}
$password = password_hash($data['password'], PASSWORD_DEFAULT);

// Insert data using prepared statements
$stmt = $conn->prepare("INSERT INTO users (name, password, ip, whitelist) VALUES (?, ?, ?, ?)");
$stmt->bind_param("sssi", $name, $password, $ip, $whitelist);

if ($stmt->execute()) {
    echo "Registration successful!";
} else {
    echo "Registration failed. Please try again.";
}

$stmt->close();
$conn->close();
?>
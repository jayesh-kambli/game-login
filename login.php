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

// Sanitize inputs
$name = filter_var($data['name'], FILTER_SANITIZE_STRING);
$password = filter_var($data['password'], FILTER_SANITIZE_STRING);
$ip = filter_var($data['ip'], FILTER_VALIDATE_IP);

if (!$ip) {
    die(json_encode(['success' => false, 'message' => 'Invalid IP address.']));
}

// Fetch user data using prepared statements
$stmt = $conn->prepare("SELECT * FROM users WHERE name = ?");
$stmt->bind_param("s", $name);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    if (password_verify($password, $row['password'])) {
        // Update IP address
        $updateStmt = $conn->prepare("UPDATE users SET ip = ? WHERE name = ?");
        $updateStmt->bind_param("ss", $ip, $name);
        if ($updateStmt->execute()) {
            // Start secure session
            session_regenerate_id(true);
            $_SESSION['user_id'] = $row['id']; // Store user ID in session
            echo json_encode(['success' => true, 'message' => 'Login successful!']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Error updating IP.']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'Invalid username or password.']);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid username or password.']);
}

$conn->close();
?>
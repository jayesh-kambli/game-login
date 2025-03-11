<?php
session_start();

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "user_data";

// Enable error reporting for debugging (remove in production)
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die(json_encode(['success' => false, 'message' => 'Database connection failed.']));
}

$data = json_decode(file_get_contents('php://input'), true);

$name = htmlspecialchars($data['name'], ENT_QUOTES, 'UTF-8');
$password = $data['password'];
$hashedPassword = hash('sha256', $password);
$ip = filter_var($data['ip'], FILTER_VALIDATE_IP);

if (!$ip) {
    die(json_encode(['success' => false, 'message' => 'Invalid IP address.']));
}

// Check if the user exists
$stmt = $conn->prepare("SELECT id, name, password FROM users WHERE name = ?");
$stmt->bind_param("s", $name);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();

    // Debugging: Check what password is stored in the database
    // var_dump($row['password']); // Uncomment this to check the hash (DO NOT use in production)

    // if (password_verify($password, $row['password'])) {
        if ($hashedPassword === $row['password']) {
        // Update IP if login is successful
        // $updateStmt = $conn->prepare("UPDATE users SET ip = ? WHERE name = ?");
        // $updateStmt->bind_param("ss", $ip, $name);
        // $updateStmt->execute();

        // Secure session
        session_regenerate_id(true);
        $_SESSION['user_id'] = $row['id'];
        $_SESSION['username'] = $row['name'];

        // header("Location: dashboard.html");
        echo json_encode(['success' => true, 'message' => 'Login successful!']);
        
    } else {
        echo json_encode(['success' => false, 'message' => 'Invalid username or password.', 'pass' => $hashedPassword, 'main' => $row['password']]);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid username or password.']);
}

$stmt->close();
$conn->close();
?>

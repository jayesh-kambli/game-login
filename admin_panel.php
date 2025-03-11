<?php
// Database Connection
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "user_data";

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die(json_encode(['success' => false, 'message' => 'Database connection failed.']));
}

// Handle actions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'], $_POST['id'])) {
    $id = intval($_POST['id']);

    if ($_POST['action'] === 'delete') {
        $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
    } elseif ($_POST['action'] === 'whitelist') {
        $stmt = $conn->prepare("UPDATE users SET whitelist = 1 WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
    } elseif ($_POST['action'] === 'unwhitelist') {
        $stmt = $conn->prepare("UPDATE users SET whitelist = 0 WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
    }

    header("Location: admin_panel.php");
    exit;
}

// Fetch users
$result = $conn->query("SELECT * FROM users");
$users = $result->fetch_all(MYSQLI_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" sizes="32x32" href="favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="favicon-16x16.png">
    <link rel="apple-touch-icon" sizes="180x180" href="apple-touch-icon.png">
    <title>Admin Panel</title>
    <style>
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; border: 1px solid black; text-align: left; }
        th { background-color: #f2f2f2; }
        .btn { padding: 5px 10px; cursor: pointer; }
        .delete { background-color: red; color: white; }
        .whitelist { background-color: green; color: white; }
        .unwhitelist { background-color: orange; color: white; }
    </style>
    <script>
        document.addEventListener("DOMContentLoaded", function () {
            const allowedAdmins = ["Jayesh", "EGO"];
            const savedName = localStorage.getItem("savedName");

            if (!savedName || !allowedAdmins.includes(savedName)) {
                document.body.innerHTML = "<h1>Access Denied</h1><p>You do not have permission to access this page.</p>";
            }
        });
    </script>
</head>
<body>
    <h2>Admin Panel - User Management</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>Name</th>
            <th>IP</th>
            <th>Whitelist</th>
            <th>Actions</th>
        </tr>
        <?php foreach ($users as $user): ?>
        <tr>
            <td><?= htmlspecialchars($user['id']) ?></td>
            <td><?= htmlspecialchars($user['name']) ?></td>
            <td><?= htmlspecialchars($user['ip']) ?></td>
            <td><?= $user['whitelist'] ? 'Yes' : 'No' ?> (Currently <?= $user['whitelist'] ? 'Whitelisted' : 'Not Whitelisted' ?>)</td>
            <td>
                <form method="POST" style="display:inline;">
                    <input type="hidden" name="id" value="<?= $user['id'] ?>">
                    <button type="submit" name="action" value="delete" class="btn delete">Delete</button>
                </form>
                <form method="POST" style="display:inline;">
                    <input type="hidden" name="id" value="<?= $user['id'] ?>">
                    <button type="submit" name="action" value="whitelist" class="btn whitelist">Whitelist</button>
                </form>
                <form method="POST" style="display:inline;">
                    <input type="hidden" name="id" value="<?= $user['id'] ?>">
                    <button type="submit" name="action" value="unwhitelist" class="btn unwhitelist">Unwhitelist</button>
                </form>
            </td>
        </tr>
        <?php endforeach; ?>
    </table>
</body>
</html>

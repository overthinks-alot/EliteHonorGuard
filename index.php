<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $registration_code = $_POST['registration_code'];

    if (isset($_POST['register'])) {
        // Registration logic
        if ($registration_code === 'ELITE2024') {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
            $stmt->execute([$username, $hashed_password]);
            $_SESSION['username'] = $username;
            header('Location: dashboard.php');
            exit();
        }
    } else {
        // Login logic
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['username'] = $username;
            header('Location: dashboard.php');
            exit();
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Elite Honor Guard Database - Login</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Elite Honor Guard Database</h1>
        <div class="login-form">
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <input type="text" name="registration_code" placeholder="Registration Code (for new users)">
                <button type="submit" name="login">Login</button>
                <button type="submit" name="register">Register</button>
            </form>
        </div>
    </div>
</body>
</html> 
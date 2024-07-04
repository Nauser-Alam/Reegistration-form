<?php
// Database connection parameters
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "mysite";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Collect form data and sanitize inputs
$user = htmlspecialchars($_POST['username']);
$email = htmlspecialchars($_POST['email']);
$pass = $_POST['password'];
$confirm_pass = $_POST['confirm_password'];

// Validate form data
if (empty($user) || empty($email) || empty($pass) || empty($confirm_pass)) {
    echo "All fields are required!";
    exit();
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo "Invalid email format!";
    exit();
}

if ($pass !== $confirm_pass) {
    echo "Passwords do not match!";
    exit();
}

// Hash the password
$hashed_password = password_hash($pass, PASSWORD_DEFAULT);

// Check if the email already exists
$sql = "SELECT * FROM users WHERE email=?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    echo "Email already exists!";
    exit();
}

// Insert user data into the database
$sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
$stmt = $conn->prepare($sql);
$stmt->bind_param("sss", $user, $email, $hashed_password);

if ($stmt->execute()) {
    echo "Registration successful!";
} else {
    echo "Error: " . $stmt->error;
}

// Close the statement and connection
$stmt->close();
$conn->close();
?>

<?php
session_start();
$db = new SQLite3('db.sqlite');

// INIT DB
$db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT
)");
$db->exec("CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY,
    filename TEXT,
    filepath TEXT,
    token TEXT UNIQUE,
    uploaded_by TEXT,
    expires_at INTEGER
)");

// LOGOUT
if (isset($_GET['logout'])) {
    setcookie('user', '', time() - 3600);
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// REGISTER
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register'])) {
    $user = trim($_POST['username']);
    $pass = $_POST['password'];
    if ($user && $pass) {
        $stmt = $db->prepare("SELECT 1 FROM users WHERE username = :u");
        $stmt->bindValue(':u', $user);
        if ($stmt->execute()->fetchArray()) {
            $error = "Username already taken.";
        } else {
            $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:u, :p)");
            $stmt->bindValue(':u', $user);
            $stmt->bindValue(':p', password_hash($pass, PASSWORD_DEFAULT));
            $stmt->execute();
            setcookie('user', $user, time() + 3600);
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        }
    }
}

// LOGIN
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $stmt = $db->prepare("SELECT * FROM users WHERE username = :u");
    $stmt->bindValue(':u', $_POST['username']);
    $userRow = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if ($userRow && password_verify($_POST['password'], $userRow['password'])) {
        setcookie('user', $userRow['username'], time() + 3600);
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $error = "Invalid login.";
    }
}

// FILE DOWNLOAD
if (isset($_GET['download'])) {
    $stmt = $db->prepare("SELECT * FROM files WHERE token = :t");
    $stmt->bindValue(':t', $_GET['download']);
    $file = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if ($file && (!$file['expires_at'] || $file['expires_at'] > time())) {
        header('Content-Disposition: attachment; filename="' . basename($file['filename']) . '"');
        readfile($file['filepath']);
    } else {
        echo "File not found or expired.";
    }
    exit;
}

// DELETE FILE
if (isset($_GET['delete']) && isset($_COOKIE['user'])) {
    $stmt = $db->prepare("SELECT * FROM files WHERE id = :id AND uploaded_by = :u");
    $stmt->bindValue(':id', (int)$_GET['delete']);
    $stmt->bindValue(':u', $_COOKIE['user']);
    $file = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if ($file) {
        @unlink($file['filepath']);
        $db->exec("DELETE FROM files WHERE id = " . (int)$_GET['delete']);
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// FILE UPLOAD
if (isset($_FILES['file']) && isset($_COOKIE['user'])) {
    $maxSize = 5 * 1024 * 1024; // 5 MB max
    $allowedTypes = ['image/jpeg','image/gif', 'image/png', 'application/pdf', 'text/plain', 'application/zip','application/rar','application/xz','application/tar','application/bz2','application/wav','application/mov','application/mp3','application/ogg','application/avi','application/ogv','application/flv',];

    $file = $_FILES['file'];

    if ($file['error'] === UPLOAD_ERR_OK) {
        if ($file['size'] > $maxSize) {
            $error = "File too large. Max size is 5 MB.";
        } elseif (!in_array(mime_content_type($file['tmp_name']), $allowedTypes)) {
            $error = "File type not allowed.";
        } else {
            if (!is_dir('uploads')) mkdir('uploads');
            $name = $file['name'];
            $tmp = $file['tmp_name'];
            $token = bin2hex(random_bytes(16));
            $path = "uploads/{$token}_" . basename($name);
            move_uploaded_file($tmp, $path);
            $expire = isset($_POST['expire']) ? time() + ((int)$_POST['expire'] * 60) : null;

            $stmt = $db->prepare("INSERT INTO files (filename, filepath, token, uploaded_by, expires_at)
                VALUES (:f, :p, :t, :u, :e)");
            $stmt->bindValue(':f', $name);
            $stmt->bindValue(':p', $path);
            $stmt->bindValue(':t', $token);
            $stmt->bindValue(':u', $_COOKIE['user']);
            $stmt->bindValue(':e', $expire);
            $stmt->execute();

            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        }
    } else {
        $error = "File upload error.";
    }
}


// RENDER PAGE
$user = $_COOKIE['user'] ?? null;
?>
<!DOCTYPE html>
<html>
<head>
    <title>PHP File Share</title>
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 30px auto; }
        input, button { padding: 5px; margin: 5px 0; }
        form { margin-bottom: 20px; }
        .file { margin: 10px 0; padding: 8px; background: #f9f9f9; border-radius: 5px; }
    </style>
</head>
<body>
<?php if ($user): ?>
    <h2>Welcome, <?=htmlspecialchars($user)?></h2>
    <a href="?logout=1">Logout</a>

    <h3>Upload File</h3>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required><br>
        Expire in minutes: <input type="number" name="expire" value="60"><br>
        <button>Upload</button>
    </form>

    <h3>Your Files</h3>
    <?php
    $now = time();
    $stmt = $db->prepare("SELECT * FROM files WHERE uploaded_by = :u AND (expires_at IS NULL OR expires_at > $now)");
    $stmt->bindValue(':u', $user);
    $files = $stmt->execute();
    while ($row = $files->fetchArray(SQLITE3_ASSOC)):
    ?>
        <div class="file">
            <?=htmlspecialchars($row['filename'])?> -
            <a href="?download=<?=$row['token']?>">Download</a> -
            <a href="?delete=<?=$row['id']?>" onclick="return confirm('Delete this file?')">Delete</a>
        </div>
    <?php endwhile; ?>

<?php else: ?>
    <h2>Login</h2>
    <form method="POST">
        <input name="username" placeholder="Username" required><br>
        <input name="password" type="password" placeholder="Password" required><br>
        <button name="login">Login</button>
    </form>

    <h2>Register</h2>
    <form method="POST">
        <input name="username" placeholder="Username" required><br>
        <input name="password" type="password" placeholder="Password" required><br>
        <button name="register">Register</button>
    </form>
    <?php if (isset($error)) echo "<p style='color:red'>$error</p>"; ?>
<?php endif; ?>
</body>
</html>

<?php
header("Content-Type: application/json");
require_once __DIR__ . "/_auth.php";

$raw = file_get_contents("php://input");
if($raw === false || trim($raw) === ""){
  auth_json_response(400, ["error" => "No data received"]);
}

$decoded = json_decode($raw, true);
if(json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)){
  auth_json_response(400, ["error" => "Invalid JSON payload"]);
}

$username = strtolower(trim((string)($decoded["username"] ?? "")));
$password = (string)($decoded["password"] ?? "");
$inviteCode = trim((string)($decoded["inviteCode"] ?? ""));
$newPassword = (string)($decoded["newPassword"] ?? "");

if($username === ""){
  auth_json_response(400, ["error" => "Username is required"]);
}

$data = load_users_data(true);
if(empty($data["users"])){
  auth_json_response(403, ["error" => "No users configured. Set INVENTORY_ADMIN_USER and INVENTORY_ADMIN_PASS."]);
}

$userIndex = -1;
foreach($data["users"] as $i => $u){
  if(strtolower((string)($u["username"] ?? "")) === $username){
    $userIndex = $i;
    break;
  }
}
if($userIndex < 0){
  auth_json_response(401, ["error" => "Invalid credentials"]);
}

$user = $data["users"][$userIndex];
if(($user["status"] ?? "active") !== "active" && ($user["status"] ?? "") !== "invited"){
  auth_json_response(403, ["error" => "Account disabled"]);
}

if($inviteCode !== ""){
  if(($user["inviteCode"] ?? "") !== $inviteCode){
    auth_json_response(401, ["error" => "Invalid invite code"]);
  }
  if(strlen($newPassword) < 6){
    auth_json_response(400, ["error" => "New password must be at least 6 characters"]);
  }
  $user["passwordHash"] = password_hash($newPassword, PASSWORD_DEFAULT);
  $user["inviteCode"] = null;
  $user["status"] = "active";
}else{
  if($password === ""){
    auth_json_response(400, ["error" => "Password is required"]);
  }
  $hash = (string)($user["passwordHash"] ?? "");
  if(!$hash || !password_verify($password, $hash)){
    auth_json_response(401, ["error" => "Invalid credentials"]);
  }
}

$user["lastLoginAt"] = gmdate("c");
$user["updatedAt"] = gmdate("c");

// create session token
$token = bin2hex(random_bytes(24));
$expiresAt = gmdate("c", time() + 60 * 60 * 12); // 12 hours
$data["sessions"][] = [
  "token" => $token,
  "userId" => $user["id"],
  "expiresAt" => $expiresAt,
  "createdAt" => gmdate("c")
];

// limit sessions to 50 total
if(count($data["sessions"]) > 50){
  $data["sessions"] = array_slice($data["sessions"], -50);
}

$data["users"][$userIndex] = $user;
save_users_data($data);

echo json_encode([
  "token" => $token,
  "username" => $user["username"],
  "displayName" => $user["displayName"] ?? $user["username"],
  "role" => $user["role"] ?? "viewer",
  "expiresAt" => $expiresAt
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

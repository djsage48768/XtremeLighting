<?php
header("Content-Type: application/json");
require_once __DIR__ . "/_auth.php";

$authUser = require_auth_user("admin");

$method = $_SERVER["REQUEST_METHOD"] ?? "GET";
$data = load_users_data(true);

if($method === "GET"){
  $users = array_map("sanitize_user", $data["users"]);
  echo json_encode(["users" => $users], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  exit;
}

$raw = file_get_contents("php://input");
if($raw === false || trim($raw) === ""){
  auth_json_response(400, ["error" => "No data received"]);
}

$decoded = json_decode($raw, true);
if(json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)){
  auth_json_response(400, ["error" => "Invalid JSON payload"]);
}

$action = (string)($decoded["action"] ?? "");

function require_user_by_id(&$data, $userId){
  $idx = find_user_index_by_id($data["users"], $userId);
  if($idx < 0){
    auth_json_response(404, ["error" => "User not found"]);
  }
  return $idx;
}

function generate_invite_code(){
  return strtoupper(substr(bin2hex(random_bytes(6)), 0, 10));
}

if($action === "createInvite"){
  $username = strtolower(trim((string)($decoded["username"] ?? "")));
  $role = strtolower(trim((string)($decoded["role"] ?? "viewer")));
  if($username === ""){
    auth_json_response(400, ["error" => "Username is required"]);
  }
  foreach($data["users"] as $u){
    if(strtolower((string)($u["username"] ?? "")) === $username){
      auth_json_response(409, ["error" => "Username already exists"]);
    }
  }
  $inviteCode = generate_invite_code();
  $data["users"][] = [
    "id" => bin2hex(random_bytes(16)),
    "username" => $username,
    "displayName" => $decoded["displayName"] ?? $username,
    "role" => in_array($role, ["viewer","editor","admin"], true) ? $role : "viewer",
    "status" => "invited",
    "passwordHash" => null,
    "inviteCode" => $inviteCode,
    "createdAt" => gmdate("c"),
    "updatedAt" => gmdate("c"),
    "lastLoginAt" => null
  ];
  save_users_data($data);
  echo json_encode(["status" => "ok", "inviteCode" => $inviteCode], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  exit;
}

if($action === "setRole"){
  $userId = (string)($decoded["userId"] ?? "");
  $role = strtolower(trim((string)($decoded["role"] ?? "")));
  if($userId === "" || !in_array($role, ["viewer","editor","admin"], true)){
    auth_json_response(400, ["error" => "Invalid role update"]);
  }
  $idx = require_user_by_id($data, $userId);
  $data["users"][$idx]["role"] = $role;
  $data["users"][$idx]["updatedAt"] = gmdate("c");
  save_users_data($data);
  echo json_encode(["status" => "ok"], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  exit;
}

if($action === "setStatus"){
  $userId = (string)($decoded["userId"] ?? "");
  $status = strtolower(trim((string)($decoded["status"] ?? "")));
  if($userId === "" || !in_array($status, ["active","disabled","invited"], true)){
    auth_json_response(400, ["error" => "Invalid status update"]);
  }
  $idx = require_user_by_id($data, $userId);
  if(($data["users"][$idx]["id"] ?? "") === ($authUser["id"] ?? "") && $status !== "active"){
    auth_json_response(400, ["error" => "You cannot disable your own account"]);
  }
  $data["users"][$idx]["status"] = $status;
  $data["users"][$idx]["updatedAt"] = gmdate("c");
  save_users_data($data);
  echo json_encode(["status" => "ok"], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  exit;
}

if($action === "resetInvite"){
  $userId = (string)($decoded["userId"] ?? "");
  if($userId === ""){
    auth_json_response(400, ["error" => "Invalid user id"]);
  }
  $idx = require_user_by_id($data, $userId);
  if(($data["users"][$idx]["id"] ?? "") === ($authUser["id"] ?? "")){
    auth_json_response(400, ["error" => "You cannot reset your own invite"]);
  }
  $data["users"][$idx]["inviteCode"] = generate_invite_code();
  $data["users"][$idx]["passwordHash"] = null;
  $data["users"][$idx]["status"] = "invited";
  $data["users"][$idx]["updatedAt"] = gmdate("c");
  save_users_data($data);
  echo json_encode(["status" => "ok", "inviteCode" => $data["users"][$idx]["inviteCode"]], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  exit;
}

auth_json_response(400, ["error" => "Unknown action"]);

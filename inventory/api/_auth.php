<?php
function auth_json_response($code, $payload){
  http_response_code($code);
  echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  exit;
}

function users_file_path(){
  return __DIR__ . "/../data/users.json";
}

function load_users_data($allowBootstrap = true){
  $file = users_file_path();
  if(!file_exists($file)){
    if($allowBootstrap){
      $adminUser = getenv("INVENTORY_ADMIN_USER") ?: "";
      $adminPass = getenv("INVENTORY_ADMIN_PASS") ?: "";
      if($adminUser !== "" && $adminPass !== ""){
        $data = [
          "version" => 1,
          "users" => [[
            "id" => bin2hex(random_bytes(16)),
            "username" => strtolower($adminUser),
            "displayName" => $adminUser,
            "role" => "admin",
            "status" => "active",
            "passwordHash" => password_hash($adminPass, PASSWORD_DEFAULT),
            "inviteCode" => null,
            "createdAt" => gmdate("c"),
            "updatedAt" => gmdate("c"),
            "lastLoginAt" => null
          ]],
          "sessions" => []
        ];
        save_users_data($data);
        return $data;
      }
    }
    return ["version" => 1, "users" => [], "sessions" => []];
  }

  $raw = file_get_contents($file);
  if($raw === false){
    auth_json_response(500, ["error" => "Could not read users file"]);
  }

  $decoded = json_decode($raw, true);
  if(json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)){
    auth_json_response(500, ["error" => "Users file is corrupted"]);
  }

  if(!isset($decoded["users"]) || !is_array($decoded["users"])) $decoded["users"] = [];
  if(!isset($decoded["sessions"]) || !is_array($decoded["sessions"])) $decoded["sessions"] = [];
  if(!isset($decoded["version"])) $decoded["version"] = 1;
  return $decoded;
}

function save_users_data($data){
  $file = users_file_path();
  $dir = dirname($file);
  if(!is_dir($dir) && !mkdir($dir, 0775, true)){
    auth_json_response(500, ["error" => "Users directory is unavailable"]);
  }
  $payload = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  if($payload === false){
    auth_json_response(500, ["error" => "Could not encode users payload"]);
  }
  $tmpFile = $file . ".tmp." . bin2hex(random_bytes(6));
  if(file_put_contents($tmpFile, $payload, LOCK_EX) === false){
    auth_json_response(500, ["error" => "Could not write users file"]);
  }
  if(!rename($tmpFile, $file)){
    @unlink($tmpFile);
    auth_json_response(500, ["error" => "Could not save users file"]);
  }
}

function role_rank($role){
  $r = strtolower((string)$role);
  if($r === "admin") return 3;
  if($r === "editor") return 2;
  return 1; // viewer
}

function get_auth_token(){
  $token = $_SERVER["HTTP_X_AUTH_TOKEN"] ?? "";
  if($token) return trim($token);
  $auth = $_SERVER["HTTP_AUTHORIZATION"] ?? "";
  if($auth && preg_match("/^Bearer\\s+(.*)$/i", $auth, $m)){
    return trim($m[1]);
  }
  return "";
}

function find_user_index_by_id($users, $userId){
  foreach($users as $i => $u){
    if(isset($u["id"]) && $u["id"] === $userId) return $i;
  }
  return -1;
}

function verify_auth_token(&$data){
  $token = get_auth_token();
  if(!$token) return null;

  $now = time();
  $sessions = $data["sessions"] ?? [];
  $updated = false;
  $session = null;
  $sessionIndex = -1;
  foreach($sessions as $i => $s){
    $exp = isset($s["expiresAt"]) ? strtotime($s["expiresAt"]) : 0;
    if($exp && $exp < $now){
      unset($sessions[$i]);
      $updated = true;
      continue;
    }
    if(isset($s["token"]) && hash_equals($s["token"], $token)){
      $session = $s;
      $sessionIndex = $i;
    }
  }
  if($updated){
    $data["sessions"] = array_values($sessions);
    save_users_data($data);
  }
  if(!$session) return null;

  $userId = $session["userId"] ?? "";
  $userIndex = find_user_index_by_id($data["users"], $userId);
  if($userIndex < 0) return null;
  $user = $data["users"][$userIndex];
  if(($user["status"] ?? "active") !== "active") return null;
  return $user;
}

function require_auth_user($requiredRole = "viewer"){
  $data = load_users_data(true);
  if(empty($data["users"])){
    auth_json_response(403, ["error" => "No users configured. Set INVENTORY_ADMIN_USER and INVENTORY_ADMIN_PASS."]);
  }
  $user = verify_auth_token($data);
  if(!$user){
    auth_json_response(401, ["error" => "Unauthorized"]);
  }
  if(role_rank($user["role"] ?? "viewer") < role_rank($requiredRole)){
    auth_json_response(403, ["error" => "Forbidden"]);
  }
  return $user;
}

function sanitize_user($u){
  return [
    "id" => $u["id"] ?? "",
    "username" => $u["username"] ?? "",
    "displayName" => $u["displayName"] ?? "",
    "role" => $u["role"] ?? "viewer",
    "status" => $u["status"] ?? "active",
    "inviteCode" => $u["inviteCode"] ?? null,
    "createdAt" => $u["createdAt"] ?? null,
    "updatedAt" => $u["updatedAt"] ?? null,
    "lastLoginAt" => $u["lastLoginAt"] ?? null
  ];
}
